// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"

	api "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"

	"github.com/intel/cri-resource-manager/pkg/dump"
	logger "github.com/intel/cri-resource-manager/pkg/log"
	"github.com/intel/cri-resource-manager/pkg/utils"

	"github.com/intel/cri-resource-manager/pkg/instrumentation"
	"go.opentelemetry.io/otel/api/key"
	"go.opentelemetry.io/otel/api/trace"
)

// Options contains the configurable options of our CRI server.
type Options struct {
	// Socket is the path of our gRPC servers unix-domain socket.
	Socket string
}

// Handler is a CRI server generic request handler.
type Handler grpc.UnaryHandler

// Interceptor is a hook that intercepts processing a request by a handler.
type Interceptor func(context.Context, string, interface{}, Handler) (interface{}, error)

// Server is the interface we expose for controlling our CRI server.
type Server interface {
	// RegisterImageService registers the provided image service with the server.
	RegisterImageService(api.ImageServiceServer) error
	// RegistersRuntimeService registers the provided runtime service with the server.
	RegisterRuntimeService(api.RuntimeServiceServer) error
	// RegisterInterceptors registers the given interceptors with the server.
	RegisterInterceptors(map[string]Interceptor) error
	// SetBypassCheckFn sets a function to check if interception should be bypassed.
	SetBypassCheckFn(func() bool)
	// Start starts the request processing loop (goroutine) of the server.
	Start() error
	// Stop stops the request processing loop (goroutine) of the server.
	Stop()
}

// server is the implementation of Server.
type server struct {
	logger.Logger
	listener     net.Listener              // socket our gRPC server listens on
	server       *grpc.Server              // our gRPC server
	options      Options                   // server options
	interceptors map[string]Interceptor    // request intercepting hooks
	chkBypassFn  func() bool               // function to check interception bypass
	runtime      *api.RuntimeServiceServer // CRI runtime service
	image        *api.ImageServiceServer   // CRI image service
}

// NewServer creates a new server instance.
func NewServer(options Options) (Server, error) {
	if !filepath.IsAbs(options.Socket) {
		return nil, serverError("invalid socket '%s', expecting absolute path",
			options.Socket)
	}

	s := &server{
		Logger:  logger.NewLogger("cri/server"),
		options: options,
	}

	return s, nil
}

// RegisterImageService registers an image service with the server.
func (s *server) RegisterImageService(service api.ImageServiceServer) error {
	if s.image != nil {
		return serverError("can't register image service, already registered")
	}

	if err := s.createGrpcServer(); err != nil {
		return err
	}

	is := service
	s.image = &is
	api.RegisterImageServiceServer(s.server, s)

	return nil
}

// RegisterRuntimeService registers a runtime service with the server.
func (s *server) RegisterRuntimeService(service api.RuntimeServiceServer) error {
	if s.runtime != nil {
		return serverError("can't register runtime server, already registered")
	}

	if err := s.createGrpcServer(); err != nil {
		return err
	}

	rs := service
	s.runtime = &rs
	api.RegisterRuntimeServiceServer(s.server, s)

	return nil
}

// RegisterInterceptors registers the given interveptors with the server.
func (s *server) RegisterInterceptors(intercept map[string]Interceptor) error {
	if s.interceptors == nil {
		s.interceptors = make(map[string]Interceptor)
	}

	for method, i := range intercept {
		if _, ok := s.interceptors[method]; ok {
			return serverError("server already has a registered interceptor for '%s'", method)
		}
		s.interceptors[method] = i
	}

	return nil
}

// SetBypassCheckFn sets a function to check if interception should be bypassed.
func (s *server) SetBypassCheckFn(fn func() bool) {
	s.chkBypassFn = fn
}

// Start starts the servers request processing goroutine.
func (s *server) Start() error {
	s.trainMessageDumper()

	s.Debug("starting server on socket %s...", s.options.Socket)
	go func() {
		s.server.Serve(s.listener)
	}()

	s.Debug("waiting for server to become ready...")
	if err := utils.WaitForServer(s.options.Socket, time.Second); err != nil {
		return serverError("starting CRI server failed: %v", err)
	}

	return nil
}

// Stop serving CRI requests.
func (s *server) Stop() {
	s.Debug("stopping server on socket %s...", s.options.Socket)
	s.server.Stop()
}

// createGrpcServer creates a gRPC server instance on our socket.
func (s *server) createGrpcServer() error {
	if s.server != nil {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(s.options.Socket), 0700); err != nil {
		return serverError("failed to create directory for socket %s: %v",
			s.options.Socket, err)
	}

	l, err := net.Listen("unix", s.options.Socket)
	if err != nil {
		if utils.ServerActiveAt(s.options.Socket) {
			return serverError("failed to create server: socket %s already in use",
				s.options.Socket)
		}
		s.Warn("removing abandoned socket '%s' in use...", s.options.Socket)
		os.Remove(s.options.Socket)
		l, err = net.Listen("unix", s.options.Socket)
		if err != nil {
			return serverError("failed to create server on socket %s: %v",
				s.options.Socket, err)
		}
	}
	s.listener = l
	s.server = grpc.NewServer(instrumentation.InjectGrpcServerTrace()...)

	return nil
}

// getInterceptor finds an interceptor for the given method.
func (s *server) getInterceptor(method string) (Interceptor, string) {
	name := method[strings.LastIndex(method, "/")+1:]

	if s.chkBypassFn != nil && s.chkBypassFn() {
		return nil, name
	}

	if fn, ok := s.interceptors[name]; ok {
		return fn, name
	}

	if fn, ok := s.interceptors["*"]; ok {
		return fn, name
	}

	return nil, name
}

// intercept processes requests with a registered interceptor or the default handler.
func (s *server) intercept(ctx context.Context, req interface{},
	info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// Notes:
	//   We record timestamps at various phases of processing a request to later
	//   calculate local, CRI-server and total request processing latencies. We
	//   wrap the original handler to get the pre- and post-communication stamps
	//   with reasonable accuracy without having to get the stamps at the client.
	//
	//   One thing that we currently fail to measure separately is the latency of
	//   internally generated CRI requests (UpdateContainerResources). These are
	//   now accounted to the local processing latency of the triggering request.

	var kind string
	var start, send, recv, end time.Time
	var sync bool

	wrapHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		send = time.Now()
		rpl, err := handler(ctx, req)
		recv = time.Now()
		return rpl, err
	}

	fn, name := s.getInterceptor(info.FullMethod)
	if fn != nil {
		kind = "intercepted"
		sync = true
	} else {
		kind = "passthrough"
		fn = func(c context.Context, n string, r interface{}, h Handler) (interface{}, error) {
			rpl, err := h(c, r)
			return rpl, err
		}
	}

	dump.RequestMessage(kind, info.FullMethod, req, sync)

	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetAttributes(key.String("kind", kind))
	}

	start = time.Now()
	rpl, err := fn(ctx, name, req, wrapHandler)
	end = time.Now()
	elapsed := end.Sub(start)

	if err != nil {
		dump.ReplyMessage(kind, info.FullMethod, err, elapsed, false)
	} else {
		dump.ReplyMessage(kind, info.FullMethod, rpl, elapsed, false)
	}

	s.collectStatistics(kind, name, start, send, recv, end)

	return rpl, err
}

// collectStatistics collects (should collect) request processing statistics.
func (s *server) collectStatistics(kind, name string, start, send, recv, end time.Time) {
	if kind == "passthrough" {
		return
	}

	pre := send.Sub(start)
	server := recv.Sub(send)
	post := end.Sub(recv)

	s.Debug(" * latency for %s: preprocess: %v, CRI server: %v, postprocess: %v, total: %v",
		name, pre, server, post, pre+server+post)
}

// trainMessageDumper pre-trains the message dumper with our full set of service methods.
func (s server) trainMessageDumper() {
	methods := []string{}
	svcinfo := s.server.GetServiceInfo()
	for _, info := range svcinfo {
		for _, m := range info.Methods {
			methods = append(methods, m.Name)
		}
	}
	dump.Train(methods)
}

// Return a formatter server error.
func serverError(format string, args ...interface{}) error {
	return fmt.Errorf("cri/server: "+format, args...)
}

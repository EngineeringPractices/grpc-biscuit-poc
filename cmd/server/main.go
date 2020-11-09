package main

import (
	"context"
	"demo/pkg/authorization"
	"demo/pkg/pb"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

type demoServer struct {
	pb.UnimplementedDemoServer
}

var _ pb.DemoServer = (*demoServer)(nil)

func (d *demoServer) Status(_ context.Context, _ *pb.StatusRequest) (*pb.Response, error) {
	return &pb.Response{Status: pb.Response_OK}, nil
}

func (d *demoServer) Create(_ context.Context, _ *pb.CreateRequest) (*pb.Response, error) {
	return &pb.Response{Status: pb.Response_OK}, nil
}

func (d *demoServer) Read(_ context.Context, _ *pb.ReadRequest) (*pb.Response, error) {
	return &pb.Response{Status: pb.Response_OK}, nil
}

func (d *demoServer) Update(_ context.Context, _ *pb.UpdateRequest) (*pb.Response, error) {
	return &pb.Response{Status: pb.Response_OK}, nil
}

func (d *demoServer) Delete(_ context.Context, _ *pb.DeleteRequest) (*pb.Response, error) {
	return &pb.Response{Status: pb.Response_OK}, nil
}

func main() {
	lis, err := net.Listen("tcp", "localhost:8888")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	pk, err := ioutil.ReadFile("./public.demo.key")
	if err != nil {
		panic(err)
	}

	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}

	i, err := authorization.NewBiscuitInterceptor(pk, logger.Named("biscuit-interceptor"))
	if err != nil {
		panic(err)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(i.Unary),
		grpc.StreamInterceptor(i.Stream),
	)

	pb.RegisterDemoServer(grpcServer, &demoServer{})

	fmt.Println("server listening on localhost:8888")
	if err := grpcServer.Serve(lis); err != nil {
		panic(err)
	}
}

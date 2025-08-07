// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Main library entry point for wg_api implementation.
use log::*;
use std::marker::PhantomData;
use std::net::{SocketAddr};
use std::sync::Arc;
use std::convert::Infallible;
use tokio::sync::Mutex;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server as HyperServer, StatusCode};
use serde_json;

use crate::wg_api_handler::ApiHandler;
use crate::wg_conf_store_srv::EtcdApiHander;
use crate::wg_network_conf_srv::{NetApiHandler, NetworkConfClient};
use etcd_rs::Client;
use systemstat::{Platform, System};
use wg_api::models::{self};

// Re-export types that might be needed
pub use hyper::Error as HyperError;

/// Builds an HTTP server using the new hyper API
pub async fn create(
    addr: &str,
    etcd_client: Client,
    network_config_client: Arc<Mutex<NetworkConfClient>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    debug!("Creating a main tokio server...");
    let addr: SocketAddr = addr.parse().expect("Failed to parse bind address");
    let server = Arc::new(Server::new(etcd_client, network_config_client));

    // Create a service factory
    let make_svc = make_service_fn(move |_conn| {
        let server = Arc::clone(&server);
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let server = Arc::clone(&server);
                async move {
                    handle_request(req, server).await
                }
            }))
        }
    });

    // Create and run the server
    let hyper_server = HyperServer::bind(&addr).serve(make_svc);
    
    debug!("Server listening on {}", addr);
    
    if let Err(e) = hyper_server.await {
        error!("Server error: {}", e);
        return Err(e.into());
    }

    Ok(())
}

async fn handle_request(
    req: Request<Body>,
    server: Arc<Server<EmptyContext>>,
) -> Result<Response<Body>, HyperError> {
    let method = req.method();
    let path = req.uri().path();
    let context = EmptyContext;

    debug!("Handling {} {}", method, path);

    let response = match (method, path) {
        (&Method::GET, "/health") => {
            match server.get_health_status(&context).await {
                Ok(health) => {
                    let json = serde_json::to_string(&health).unwrap_or_default();
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Body::from(json))
                        .unwrap()
                }
                Err(e) => {
                    error!("Health check failed: {:?}", e);
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Health check failed"))
                        .unwrap()
                }
            }
        }
        (&Method::GET, "/system") => {
            match server.get_system_info(&context).await {
                Ok(sys_info) => {
                    let json = serde_json::to_string(&sys_info).unwrap_or_default();
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Body::from(json))
                        .unwrap()
                }
                Err(e) => {
                    error!("System info failed: {:?}", e);
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("System info failed"))
                        .unwrap()
                }
            }
        }
        (&Method::POST, "/namespaces") => {
            // Parse request body
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
            match serde_json::from_slice::<Vec<models::WgNamespace>>(&body_bytes) {
                Ok(namespaces) => {
                    match server.create_namespace(&namespaces, &context).await {
                        Ok(_) => {
                            Response::builder()
                                .status(StatusCode::CREATED)
                                .body(Body::from("Namespaces created"))
                                .unwrap()
                        }
                        Err(e) => {
                            error!("Create namespace failed: {:?}", e);
                            Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Failed to create namespaces: {:?}", e)))
                                .unwrap()
                        }
                    }
                }
                Err(e) => {
                    error!("Invalid JSON: {}", e);
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("Invalid JSON"))
                        .unwrap()
                }
            }
        }
        (&Method::DELETE, "/namespaces") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
            match serde_json::from_slice::<Vec<models::WgNamespace>>(&body_bytes) {
                Ok(namespaces) => {
                    match server.delete_namespace(&namespaces, &context).await {
                        Ok(_) => {
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from("Namespaces deleted"))
                                .unwrap()
                        }
                        Err(e) => {
                            error!("Delete namespace failed: {:?}", e);
                            Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Failed to delete namespaces: {:?}", e)))
                                .unwrap()
                        }
                    }
                }
                Err(e) => {
                    error!("Invalid JSON: {}", e);
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("Invalid JSON"))
                        .unwrap()
                }
            }
        }
        (&Method::GET, "/namespaces") => {
            match server.list_namespaces(None, &context).await {
                Ok(namespaces) => {
                    let json = serde_json::to_string(&namespaces).unwrap_or_default();
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Body::from(json))
                        .unwrap()
                }
                Err(e) => {
                    error!("List namespaces failed: {:?}", e);
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Failed to list namespaces"))
                        .unwrap()
                }
            }
        }
        (&Method::POST, "/users") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
            match serde_json::from_slice::<Vec<models::WgUser>>(&body_bytes) {
                Ok(users) => {
                    match server.create_user(&users, &context).await {
                        Ok(_) => {
                            Response::builder()
                                .status(StatusCode::CREATED)
                                .body(Body::from("Users created"))
                                .unwrap()
                        }
                        Err(e) => {
                            error!("Create user failed: {:?}", e);
                            Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Failed to create users: {:?}", e)))
                                .unwrap()
                        }
                    }
                }
                Err(e) => {
                    error!("Invalid JSON: {}", e);
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("Invalid JSON"))
                        .unwrap()
                }
            }
        }
        (&Method::DELETE, "/users") => {
            let body_bytes = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
            match serde_json::from_slice::<Vec<models::WgUser>>(&body_bytes) {
                Ok(users) => {
                    match server.delete_user(&users, &context).await {
                        Ok(_) => {
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from("Users deleted"))
                                .unwrap()
                        }
                        Err(e) => {
                            error!("Delete user failed: {:?}", e);
                            Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(format!("Failed to delete users: {:?}", e)))
                                .unwrap()
                        }
                    }
                }
                Err(e) => {
                    error!("Invalid JSON: {}", e);
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("Invalid JSON"))
                        .unwrap()
                }
            }
        }
        _ => {
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not Found"))
                .unwrap()
        }
    };

    Ok(response)
}

// Simplified context for compatibility
#[derive(Clone)]
pub struct EmptyContext;

#[derive(Clone)]
pub struct XSpanIdString(pub String);

impl EmptyContext {
    pub fn get(&self) -> XSpanIdString {
        XSpanIdString("default-span".to_string())
    }
}

// Error type for API responses
#[derive(Debug)]
pub struct ApiError(String);

impl From<String> for ApiError {
    fn from(s: String) -> Self {
        ApiError(s)
    }
}

impl From<&str> for ApiError {
    fn from(s: &str) -> Self {
        ApiError(s.to_string())
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "API Error: {}", self.0)
    }
}

impl std::error::Error for ApiError {}

#[derive(Clone)]
pub struct Server<C> {
    marker: PhantomData<C>,
    etcd_client: Client,
    network_config_client: Arc<Mutex<NetworkConfClient>>,
}

impl<C> AsRef<Arc<Mutex<NetworkConfClient>>> for Server<C> {
    fn as_ref(&self) -> &Arc<Mutex<NetworkConfClient>> {
        &self.network_config_client
    }
}

impl<C> AsRef<Client> for Server<C> {
    fn as_ref(&self) -> &Client {
        &self.etcd_client
    }
}

impl<C> Server<C> {
    pub fn new(etcd_client: Client, network_config_client: Arc<Mutex<NetworkConfClient>>) -> Self {
        debug!("Creating a openapi server object, with etcd client and linux networking utils enabled...");
        Server {
            marker: PhantomData,
            etcd_client,
            network_config_client,
        }
    }
}

pub trait InternalApi {}

// Implementation of the main API methods
impl<C> Server<C>
where
    C: Clone + Send + Sync,
{
    pub async fn get_system_info(&self, _context: &C) -> Result<models::SysInfo, ApiError> {
        let mut sysinfo = models::SysInfo {
            file_system: None,
            load_avg: None,
            network: None,
            memory: None,
            network_stats: None,
        };

        let sys = System::new();
        
        // File system info
        if let Ok(mounts) = sys.mounts() {
            let ret = mounts
                .iter()
                .map(|fs| models::FileSystem {
                    mount: Some(fs.fs_mounted_on.clone()),
                    free: Some(fs.free.as_u64() as i64),
                    avail: Some(fs.avail.as_u64() as i64),
                    total: Some(fs.total.as_u64() as i64),
                })
                .collect::<Vec<_>>();
            sysinfo.file_system = Some(ret);
        }

        // Network info
        if let Ok(networks) = sys.networks() {
            let ret = networks
                .iter()
                .map(|(name, network)| {
                    let addr = network
                        .addrs
                        .iter()
                        .map(|addr| format!("{:?}", addr))
                        .collect::<Vec<_>>();

                    models::Network {
                        name: Some(name.clone()),
                        addrs: Some(addr),
                    }
                })
                .collect::<Vec<_>>();
            sysinfo.network = Some(ret);
        }

        // Network stats
        if let Ok(networks) = sys.networks() {
            let ret = networks
                .iter()
                .filter_map(|(name, _)| {
                    sys.network_stats(name.as_str()).ok().map(|stats| {
                        models::NetworkStats {
                            name: Some(name.clone()),
                            rx_bytes: Some(stats.rx_bytes.as_u64() as i64),
                            tx_bytes: Some(stats.tx_bytes.as_u64() as i64),
                            rx_packets: Some(stats.rx_packets as i64),
                            tx_packets: Some(stats.tx_packets as i64),
                            rx_errors: Some(stats.rx_errors as i64),
                            tx_errors: Some(stats.tx_errors as i64),
                        }
                    })
                })
                .collect::<Vec<_>>();
            sysinfo.network_stats = Some(ret);
        }

        // Load average
        if let Ok(load) = sys.load_average() {
            sysinfo.load_avg = Some(models::LoadAvg {
                one: Some((load.one * 10000.0) as i32),
                five: Some((load.five * 10000.0) as i32),
                fifteen: Some((load.fifteen * 10000.0) as i32),
            });
        }

        // Memory info
        if let Ok(mem) = sys.memory() {
            sysinfo.memory = Some(models::Memory {
                total: Some(mem.total.as_u64() as i64),
                free: Some(mem.free.as_u64() as i64),
            });
        }

        Ok(sysinfo)
    }

    pub async fn get_health_status(&self, _context: &C) -> Result<models::HealthStatus, ApiError> {
        Ok(models::HealthStatus {
            status: Some("OK".to_string()),
        })
    }

    pub async fn create_namespace(
        &self,
        wg_namespace: &Vec<models::WgNamespace>,
        _context: &C,
    ) -> Result<(), ApiError> {
        debug!("create_namespace called with {} namespaces", wg_namespace.len());
        
        for namespace in wg_namespace {
            match self.create_namespace_handler(namespace, false, true, true).await {
                Err(e) => {
                    warn!("Cannot create namespace {}, reason: {}", namespace.name, e);
                    let _ = self.delete_namespace_handler(namespace).await;
                    return Err(format!("Failed to create namespace: {}", e).into());
                }
                Ok(_) => {
                    debug!("Successfully created namespace {}", namespace.name);
                }
            }
        }
        
        Ok(())
    }

    pub async fn delete_namespace(
        &self,
        wg_namespace: &Vec<models::WgNamespace>,
        _context: &C,
    ) -> Result<(), ApiError> {
        debug!("delete_namespace called with {} namespaces", wg_namespace.len());
        
        for namespace in wg_namespace {
            if let Err(e) = self.delete_namespace_handler(namespace).await {
                return Err(format!("Failed to delete namespace: {}", e).into());
            }
        }
        
        Ok(())
    }

    pub async fn list_namespaces(
        &self,
        wg_namespace: Option<&Vec<models::WgNamespace>>,
        _context: &C,
    ) -> Result<Vec<models::WgNamespaceDetail>, ApiError> {
        debug!("list_namespaces called");
        
        if let Some(namespaces) = wg_namespace {
            let mut details = Vec::new();
            for ns in namespaces {
                if let Ok(detail) = self.get_namespace_detail(&ns.name).await {
                    details.push(detail);
                }
            }
            Ok(details)
        } else {
            // Get all namespaces from etcd
            let all_namespaces = AsRef::<Client>::as_ref(self).get_namespace_summary().await;
            if let Some(namespaces) = all_namespaces {
                let mut details = Vec::new();
                for namespace_name in namespaces {
                    if let Ok(detail) = self.get_namespace_detail(&namespace_name).await {
                        details.push(detail);
                    }
                }
                Ok(details)
            } else {
                Ok(Vec::new())
            }
        }
    }

    pub async fn create_user(
        &self,
        wg_users: &Vec<models::WgUser>,
        _context: &C,
    ) -> Result<(), ApiError> {
        debug!("create_user called with {} users", wg_users.len());
        
        for user in wg_users {
            match self.create_wireguard_user(user, false, false).await {
                Ok(_) => {
                    debug!("Successfully created wireguard user {}", user.name);
                }
                Err(e) => {
                    warn!("Cannot create user {}/{}, reason: {}", user.namespace, user.name, e);
                    return Err(format!("Failed to create user: {}", e).into());
                }
            }
        }
        
        Ok(())
    }

    pub async fn delete_user(
        &self,
        wg_users: &Vec<models::WgUser>,
        _context: &C,
    ) -> Result<(), ApiError> {
        debug!("delete_user called with {} users", wg_users.len());
        
        for user in wg_users {
            match self.delete_wireguard_user(user).await {
                Ok(_) => {
                    debug!("Successfully deleted wireguard user {}", user.name);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!("User not found (OK): {}", user.name);
                }
                Err(e) => {
                    warn!("Cannot delete user {}, reason: {}", user.name, e);
                    return Err(format!("Failed to delete user: {}", e).into());
                }
            }
        }
        
        Ok(())
    }
}
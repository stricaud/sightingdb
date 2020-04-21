extern crate ansi_term;
extern crate clap;
extern crate daemonize;
extern crate dirs;
extern crate qstring;

mod acl;
mod attribute;
mod db;
mod sighting_configure;
mod sighting_reader;
mod sighting_writer;

use clap::Arg;
use std::sync::Arc;
use std::sync::Mutex;

use ansi_term::Color::Red;
use daemonize::Daemonize;
use ini::Ini;

use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

use qstring::QString;

use serde::{Deserialize, Serialize};

use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};

pub struct SharedState {
    pub db: db::Database,
    pub authenticate: bool,
}

impl SharedState {
    pub fn new() -> Self {
        Self {
            db: db::Database::new(),
            authenticate: true,
        }
    }
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
pub struct Message {
    message: String,
}

#[derive(Serialize)]
pub struct InfoData {
    implementation: String,
    version: String,
    vendor: String,
    author: String,
}

fn help(_req: HttpRequest) -> impl Responder {
    "Sighting Daemon, written by Sebastien Tricaud, (C) Devo Inc. 2019
REST Endpoints:
\t/w: write (GET)
\t/wb: write in bulk mode (POST)
\t/r: read (GET)
\t/rs: read with statistics (GET)
\t/rb: read in bulk mode (POST)
\t/rbs: read with statistics in bulk mode (POST)
\t/d: delete (GET)
\t/c: configure (GET)
\t/i: info (GET)
"
}

fn read_with_stats(data: web::Data<Arc<Mutex<SharedState>>>, _req: HttpRequest) -> impl Responder {
    let sharedstate = &mut *data.lock().unwrap();

    let (_, path) = _req.path().split_at(4);
    if sharedstate.authenticate {
        let http_header_auth = _req.head().headers.get("Authorization");
        match http_header_auth {
            Some(apikey) => {
                let can_read = acl::can_read(&mut sharedstate.db, apikey.to_str().unwrap(), path);
                if !can_read {
                    return HttpResponse::Ok().json(Message {
                        message: String::from("API key not found."),
                    });
                }
            }
            None => {
                return HttpResponse::Ok().json(Message {
                    message: String::from("Please add the API key in the Authorization headers."),
                });
            }
        }
    }
    let query_string = QString::from(_req.query_string());
    let val = query_string.get("val");
    match val {
        Some(v) => {
            let ans = sighting_reader::read(&mut sharedstate.db, path, v, true);
            HttpResponse::Ok().body(ans)
        }
        None => HttpResponse::Ok().json(Message {
            message: String::from("Error: val= not found!"),
        }),
    }
}
fn read(data: web::Data<Arc<Mutex<SharedState>>>, _req: HttpRequest) -> impl Responder {
    let sharedstate = &mut *data.lock().unwrap();

    let (_, path) = _req.path().split_at(3);
    if sharedstate.authenticate {
        let http_header_auth = _req.head().headers.get("Authorization");
        match http_header_auth {
            Some(apikey) => {
                let can_read = acl::can_read(&mut sharedstate.db, apikey.to_str().unwrap(), path);
                if !can_read {
                    return HttpResponse::Ok().json(Message {
                        message: String::from("API key not found."),
                    });
                }
            }
            None => {
                return HttpResponse::Ok().json(Message {
                    message: String::from("Please add the API key in the Authorization headers."),
                });
            }
        }
    }

    let query_string = QString::from(_req.query_string());
    let val = query_string.get("val");
    match val {
        Some(v) => {
            let ans = sighting_reader::read(&mut sharedstate.db, path, v, false);
            HttpResponse::Ok().body(ans)
        }
        None => HttpResponse::Ok().json(Message {
            message: String::from("Error: val= not found!"),
        }),
    }
}

// fn write(db: web::Data<Mutex<db::Database>>, _req: HttpRequest) -> impl Responder {
fn write(data: web::Data<Arc<Mutex<SharedState>>>, _req: HttpRequest) -> HttpResponse {
    let sharedstate = &mut *data.lock().unwrap();

    // println!("{:?}", _req.path());
    let (_, path) = _req.path().split_at(3); // We remove '/w/'

    if sharedstate.authenticate {
        let http_header_auth = _req.head().headers.get("Authorization");
        match http_header_auth {
            Some(apikey) => {
                let can_write = acl::can_write(&mut sharedstate.db, apikey.to_str().unwrap(), path);
                if !can_write {
                    let mut error_msg = String::from("Cannot write to namespace: /");
                    error_msg.push_str(path);
                    return HttpResponse::Ok().json(Message { message: error_msg });
                }
            }
            None => {
                return HttpResponse::Ok().json(Message {
                    message: String::from("Please add the API key in the Authorization headers."),
                });
            }
        }
    }

    let query_string = QString::from(_req.query_string());

    let val = query_string.get("val");
    match val {
        Some(v) => {
            let timestamp = query_string.get("timestamp").unwrap_or("0");
            let timestamp_i = timestamp.parse::<i64>().unwrap_or(0);
            let could_write = sighting_writer::write(&mut sharedstate.db, path, v, timestamp_i);
            if could_write {
                HttpResponse::Ok().json(Message {
                    message: String::from("ok"),
                })
            } else {
                HttpResponse::Ok().json(Message {
                    message: String::from("Could not write request!"),
                })
            }
        }
        None => HttpResponse::BadRequest().json(Message {
            message: String::from("Did not received a val= argument in the query string."),
        }),
    }
}

fn configure(_req: HttpRequest) -> impl Responder {
    "configure"
}

#[derive(Serialize, Deserialize)]
pub struct PostData {
    items: Vec<BulkSighting>,
}

#[derive(Serialize, Deserialize)]
pub struct BulkSighting {
    namespace: String,
    value: String,
    timestamp: Option<i64>,
}

fn read_bulk(
    data: web::Data<Arc<Mutex<SharedState>>>,
    postdata: web::Json<PostData>,
    _req: HttpRequest,
) -> impl Responder {
    let sharedstate = &mut *data.lock().unwrap();

    let mut json_response = String::from("{\n\t\"items\": [\n");

    for v in &postdata.items {
        if sharedstate.authenticate {
            let http_header_auth = _req.head().headers.get("Authorization");
            match http_header_auth {
                Some(apikey) => {
                    let can_read = acl::can_read(
                        &mut sharedstate.db,
                        apikey.to_str().unwrap(),
                        v.namespace.as_str(),
                    );
                    if !can_read {
                        return HttpResponse::Ok().json(Message {
                            message: String::from("API key not found."),
                        });
                    }
                }
                None => {
                    return HttpResponse::Ok().json(Message {
                        message: String::from(
                            "Please add the API key in the Authorization headers.",
                        ),
                    });
                }
            }
        }

        let ans = sighting_reader::read(
            &mut sharedstate.db,
            v.namespace.as_str(),
            v.value.as_str(),
            false,
        );

        json_response.push_str("\t\t");
        json_response.push_str(&ans);
        json_response.push_str(",\n");
    }
    json_response.pop();
    json_response.pop(); // We don't need the last ,
    json_response.push_str("\n"); // however we need the line return :)

    json_response.push_str("\t]\n}\n");
    HttpResponse::Ok().body(json_response)
}

fn read_bulk_with_stats(
    data: web::Data<Arc<Mutex<SharedState>>>,
    postdata: web::Json<PostData>,
    _req: HttpRequest,
) -> impl Responder {
    let sharedstate = &mut *data.lock().unwrap();

    let mut json_response = String::from("{\n\t\"items\": [\n");

    for v in &postdata.items {
        if sharedstate.authenticate {
            let http_header_auth = _req.head().headers.get("Authorization");
            match http_header_auth {
                Some(apikey) => {
                    let can_read = acl::can_read(
                        &mut sharedstate.db,
                        apikey.to_str().unwrap(),
                        v.namespace.as_str(),
                    );
                    if !can_read {
                        return HttpResponse::Ok().json(Message {
                            message: String::from("API key not found."),
                        });
                    }
                }
                None => {
                    return HttpResponse::Ok().json(Message {
                        message: String::from(
                            "Please add the API key in the Authorization headers.",
                        ),
                    });
                }
            }
        }

        let ans = sighting_reader::read(
            &mut sharedstate.db,
            v.namespace.as_str(),
            v.value.as_str(),
            true,
        );

        json_response.push_str("\t\t");
        json_response.push_str(&ans);
        json_response.push_str(",\n");
    }
    json_response.pop();
    json_response.pop(); // We don't need the last ,
    json_response.push_str("\n"); // however we need the line return :)

    json_response.push_str("\t]\n}\n");
    HttpResponse::Ok().body(json_response)
}

fn write_bulk(
    data: web::Data<Arc<Mutex<SharedState>>>,
    postdata: web::Json<PostData>,
    _req: HttpRequest,
) -> impl Responder {
    let sharedstate = &mut *data.lock().unwrap();
    let mut could_write = false;

    for v in &postdata.items {
        if !v.value.is_empty() {
            // There is no need to write a value that does not exists
            let http_header_auth = _req.head().headers.get("Authorization");
            match http_header_auth {
                Some(apikey) => {
                    let can_write = acl::can_write(
                        &mut sharedstate.db,
                        apikey.to_str().unwrap(),
                        v.namespace.as_str(),
                    );
                    if !can_write {
                        return HttpResponse::Ok().json(Message {
                            message: String::from("API key not found."),
                        });
                    }
                }
                None => {
                    return HttpResponse::Ok().json(Message {
                        message: String::from(
                            "Please add the API key in the Authorization headers.",
                        ),
                    });
                }
            }

            let timestamp = v.timestamp.unwrap_or(0);
            could_write = sighting_writer::write(
                &mut sharedstate.db,
                v.namespace.as_str(),
                v.value.as_str(),
                timestamp,
            );
        }
    }

    if could_write {
        return HttpResponse::Ok().json(Message {
            message: String::from("ok"),
        });
    }
    HttpResponse::Ok().json(Message {
        message: String::from("Invalid base64 encoding (base64 url with non padding) value"),
    })
}

fn delete(data: web::Data<Arc<Mutex<SharedState>>>, _req: HttpRequest) -> HttpResponse {
    let sharedstate = &mut *data.lock().unwrap();

    let (_, path) = _req.path().split_at(3); // We remove '/w/'
    let http_header_auth = _req.head().headers.get("Authorization");
    match http_header_auth {
        Some(apikey) => {
            let can_write = acl::can_write(&mut sharedstate.db, apikey.to_str().unwrap(), path);
            if !can_write {
                let mut error_msg = String::from("Cannot write to namespace: /");
                error_msg.push_str(path);
                return HttpResponse::Ok().json(Message { message: error_msg });
            }
        }
        None => {
            return HttpResponse::Ok().json(Message {
                message: String::from("Please add the API key in the Authorization headers."),
            });
        }
    }

    let deleted = sharedstate.db.delete(path);
    if !deleted {
        return HttpResponse::Ok().json(Message {
            message: String::from("Namespace not found, nothing was deleted."),
        });
    }

    HttpResponse::Ok().json(Message {
        message: String::from("ok"),
    })
}

fn create_home_config() {
    let mut home_config = dirs::home_dir().unwrap();
    home_config.push(".sightingdb");
    match fs::create_dir_all(home_config) {
        Ok(_) => {}
        Err(e) => {
            println!("Error creating home configuration: {}", e);
        }
    }
}

fn sightingdb_get_config() -> Result<String, &'static str> {
    let ini_file = PathBuf::from("/etc/sightingdb/sightingdb.conf");
    let mut home_ini_file = dirs::home_dir().unwrap();

    let can_open = Path::new(&ini_file).exists();
    if can_open {
        return Ok(String::from(ini_file.to_str().unwrap()));
    }

    home_ini_file.push(".sightingdb");
    home_ini_file.push("sightingdb.conf");

    let can_open = Path::new(&home_ini_file).exists();
    if can_open {
        return Ok(String::from(home_ini_file.to_str().unwrap()));
    }

    Err("Cannot locate sightingdb.conf in neither from the -c flag, /etc/sightingdb or ~/.sightingdb/")
}

fn sightingdb_get_pid() -> String {
    let can_create_file = File::create("/var/run/sightingdb.pid");
    match can_create_file {
        Ok(_) => String::from("/var/run/sightingdb.pid"),
        Err(..) => {
            let mut home_pid = dirs::home_dir().unwrap();
            home_pid.push(".sightingdb");
            home_pid.push("sighting-daemon.pid");
            let pid_file = home_pid.to_str().unwrap();
            let can_create_home_pid_file = File::create(pid_file);
            match can_create_home_pid_file {
                Ok(_) => String::from(pid_file),
                Err(..) => {
                    println!("Cannot write pid to /var/run not ~/.sightingdb/, using current dir: sightingdb.pid");
                    String::from("./sightingdb.pid")
                }
            }
        }
    }
    // return String::from("./sightingdb.pid"); This is the default, but since the compiler gives a warning, I comment this out
}

fn main() {
    create_home_config();

    let sharedstate = Arc::new(Mutex::new(SharedState::new()));

    let matches = clap::App::new("SightingDB")
        .version("0.4")
        .author("Sebastien Tricaud <sebastien.tricaud@devo.com>")
        .about("Sightings Database")
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .get_matches();

    // match matches.occurrences_of("v") {
    //     0 => println!("No verbose info"),
    //     1 => println!("Some verbose info"),
    //     2 => println!("Tons of verbose info"),
    //     3 | _ => println!("Don't be crazy"),
    // }

    let configarg = matches.value_of("config");
    let configstr;
    match configarg {
        Some(_configstr) => {
            configstr = _configstr.to_string();
        }
        None => {
            let sightingdb_ini_file = sightingdb_get_config().unwrap();
            configstr = sightingdb_ini_file;
        }
    }

    println!("Using configuration file: {}", configstr);
    let configpath = Path::new(&configstr);
    let config = Ini::load_from_file(&configstr).unwrap();
    println!("Config path:{}", configpath.parent().unwrap().display());

    let daemon_config = config.section(Some("daemon")).unwrap();

    let listen_ip = daemon_config.get("listen_ip").unwrap();
    let listen_port = daemon_config.get("listen_port").unwrap();

    let server_address = format!("{}:{}", listen_ip, listen_port);

    let welcome_string = Red.paint("Starting Sighting Daemon").to_string();
    println!("{}", welcome_string);

    let use_ssl;
    match daemon_config.get("ssl").unwrap().as_ref() {
        "false" => use_ssl = false,
        _ => use_ssl = true, // no mistake, only false can start the unsecure server.
    }
    match daemon_config.get("authenticate").unwrap().as_ref() {
        "false" => {
            sharedstate.lock().unwrap().authenticate = false;
        }
        _ => sharedstate.lock().unwrap().authenticate = true, // no mistake, only false can start the unsecure server.
    }
    if !sharedstate.lock().unwrap().authenticate {
        let auth_string = Red
            .paint("No authentication used for the database.")
            .to_string();
        println!("{}", auth_string);
    }

    let mut ssl_cert: PathBuf;
    let ssl_cert_config = daemon_config.get("ssl_cert").unwrap();
    if ssl_cert_config.starts_with('/') {
        ssl_cert = PathBuf::from(ssl_cert_config);
    } else {
        ssl_cert = PathBuf::from(configpath.parent().unwrap());
        ssl_cert.push(&ssl_cert_config);
    }

    let mut ssl_key: PathBuf;
    let ssl_key_config = daemon_config.get("ssl_key").unwrap();
    if ssl_key_config.starts_with('/') {
        ssl_key = PathBuf::from(ssl_key_config);
    } else {
        ssl_key = PathBuf::from(configpath.parent().unwrap());
        ssl_key.push(&ssl_key_config);
    }

    match daemon_config.get("daemonize").unwrap().as_ref() {
        "true" => {
            let stdout = File::create(daemon_config.get("log_out").unwrap()).unwrap();
            let stderr = File::create(daemon_config.get("log_err").unwrap()).unwrap();

            let pid_file = sightingdb_get_pid();
            match Daemonize::new().pid_file(pid_file).stdout(stdout).stderr(stderr).start() {
                Ok(_) => {},
                Err(e) => println!("Error starting daemon: {}", e),
            }
        },
        "false" => println!("This daemon is not daemonized. To run in background, set 'daemonize = true' in sigthing-daemon.ini"),
        _ => println!("Unknown daemon setting. Starting in foreground."),
    }

    if use_ssl {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
        builder
            .set_private_key_file(ssl_key, SslFiletype::PEM)
            .unwrap();
        builder
            .set_certificate_chain_file(ssl_cert.to_str().unwrap())
            .unwrap();

        // routes:
        // w -> write
        // r -> read
        // c -> config (push all to disk, alway in memory, both)
        // i -> info
        // untyped -> things that have an incorrect type match

        let post_limit: usize = daemon_config
            .get("post_limit")
            .unwrap()
            .parse()
            .unwrap_or(2_500_000_000);

        HttpServer::new(move || {
            App::new()
                .data(sharedstate.clone())
                .route("/r/*", web::get().to(read))
                .route("/rb", web::post().to(read_bulk))
                .route("/rs/*", web::get().to(read_with_stats))
                .route("/rbs", web::post().to(read_bulk_with_stats))
                .route("/w/*", web::get().to(write))
                .route("/wb", web::post().to(write_bulk))
                .route("/c/*", web::get().to(configure))
                .route("/i", web::get().to(info))
                .route("/d/*", web::get().to(delete))
                .default_service(web::to(help))
                .data(web::JsonConfig::default().limit(post_limit))
        })
        .bind_ssl(server_address, builder)
        .unwrap()
        .run()
        .unwrap();
    }
}

fn info(_req: HttpRequest) -> impl Responder {
    let info_data = InfoData {
        implementation: String::from("SightingDB"),
        version: String::from("0.0.1"),
        vendor: String::from("Devo"),
        author: String::from("Sebastien Tricaud"),
    };
    HttpResponse::Ok().json(&info_data)
}

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use spl_token::instruction as token_instruction;
use bs58;
use base64::{Engine as _, engine::general_purpose};
use log::{info, error};
use std::str::FromStr;

// --- Response & Request Structs ---

#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize, Debug)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize, Debug)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize, Debug)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct InstructionResponse {
    program_id: String,
    accounts: Vec<AccountMetaResponse>,
    instruction_data: String,
}

#[derive(Serialize)]
struct AccountMetaResponse {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

// --- Handlers ---

// POST /keypair
async fn generate_keypair() -> impl Responder {
    info!("Handling POST /keypair");
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();

    info!("Generated keypair: pubkey={}", pubkey);
    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: KeypairResponse { pubkey, secret },
    })
}

// POST /token/create
async fn create_token(req: web::Json<CreateTokenRequest>) -> impl Responder {
    info!("Handling POST /token/create with request: {:?}", req);
    let mint_authority = match Pubkey::from_str(&req.mint_authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            error!("Invalid mint authority public key");
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid mint authority public key".to_string(),
            });
        }
    };
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            error!("Invalid mint public key");
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid mint public key".to_string(),
            });
        }
    };
    let instruction = token_instruction::initialize_mint(
        &spl_token::id(), &mint, &mint_authority, None, req.decimals
    ).unwrap();
    let accounts = instruction.accounts.into_iter().map(|acc| AccountMetaResponse {
        pubkey: acc.pubkey.to_string(), is_signer: acc.is_signer, is_writable: acc.is_writable
    }).collect();
    info!("Successfully created token instruction for mint: {}", mint);
    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: InstructionResponse {
            program_id: spl_token::id().to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        },
    })
}

// POST /token/mint
async fn mint_token(req: web::Json<MintTokenRequest>) -> impl Responder {
    info!("Handling POST /token/mint with request: {:?}", req);
    let mint = match Pubkey::from_str(&req.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            error!("Invalid mint public key");
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false, error: "Invalid mint public key".to_string()
            });
        }
    };
    let destination = match Pubkey::from_str(&req.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            error!("Invalid destination public key");
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false, error: "Invalid destination public key".to_string()
            });
        }
    };
    let authority = match Pubkey::from_str(&req.authority) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            error!("Invalid authority public key");
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false, error: "Invalid authority public key".to_string()
            });
        }
    };
    let instruction = token_instruction::mint_to(
        &spl_token::id(), &mint, &destination, &authority, &[], req.amount
    ).unwrap();
    let accounts = instruction.accounts.into_iter().map(|acc| AccountMetaResponse {
        pubkey: acc.pubkey.to_string(), is_signer: acc.is_signer, is_writable: acc.is_writable
    }).collect();
    info!("Successfully created mint instruction for amount: {}", req.amount);
    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: InstructionResponse {
            program_id: spl_token::id().to_string(),
            accounts,
            instruction_data: general_purpose::STANDARD.encode(&instruction.data),
        },
    })
}

// POST /message/sign
async fn sign_message(req: web::Json<SignMessageRequest>) -> impl Responder {
    info!("Handling POST /message/sign");

    // Validate presence of fields
    if req.message.is_empty() || req.secret.is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Missing required fields".to_string(),
        });
    }

    // Decode secret key from base58
    let keypair_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            error!("Failed to decode base58 secret key");
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid secret key format.".to_string(),
            });
        }
    };

    // Create Keypair from bytes
    let keypair = match Keypair::from_bytes(&keypair_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            error!("Failed to create keypair from bytes");
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid secret key format.".to_string(),
            });
        }
    };

    // Sign the message
    let signature = keypair.sign_message(req.message.as_bytes());

    // Encode signature as base64
    let signature_base64 = general_purpose::STANDARD.encode(signature.as_ref());

    // Get public key in base58
    let public_key_base58 = keypair.pubkey().to_string();

    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: SignMessageResponse {
            signature: signature_base64,
            public_key: public_key_base58,
            message: req.message.clone(),
        },
    })
}

// --- Main function ---

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    println!("🚀 Starting server at http://127.0.0.1:8080");
    HttpServer::new(|| {
        App::new()
            .route("/keypair", web::post().to(generate_keypair))
            .route("/token/create", web::post().to(create_token))
            .route("/token/mint", web::post().to(mint_token))
            .route("/message/sign", web::post().to(sign_message))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

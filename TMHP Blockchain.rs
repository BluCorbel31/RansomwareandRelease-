use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use serde::{Deserialize, Serialize};
use ring::digest::{self, SHA256};
use ring::signature::{Ed25519KeyPair, Signature, KeyPair, UnparsedPublicKey};
use ring::rand::{SystemRandom, SecureRandom};
use serde_json;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{error::Error, io::{self, Read}};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// Define Transaction structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Transaction {
    sender: String,
    recipient: String,
    amount: f64,
    signature: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
}

impl Transaction {
    // Function to sign the transaction
    fn sign(&mut self, key_pair: &Ed25519KeyPair) -> Result<(), Box<dyn Error>> {
        let data = serde_json::to_string(&self)?;
        let signature = key_pair.sign(data.as_bytes());
        self.signature = Some(signature.as_ref().to_vec());
        self.public_key = Some(key_pair.public_key().as_ref().to_vec());
        Ok(())
    }

    // Function to verify the transaction's signature
    fn verify_signature(&self) -> Result<(), Box<dyn Error>> {
        if let (Some(public_key), Some(signature)) = (&self.public_key, &self.signature) {
            let data = serde_json::to_string(&self)?;
            let public_key = UnparsedPublicKey::new(&ring::signature::ED25519, public_key);
            let signature = Signature::new(signature.as_ref());
            public_key.verify(data.as_bytes(), signature)?;
            Ok(())
        } else {
            Err("Signature or public key is missing".into())
        }
    }
}

// Define Block structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Block {
    index: u64,
    timestamp: u64,
    transactions: Vec<Transaction>,
    previous_hash: String,
    hash: String,
    nonce: u64,
}

impl Block {
    // Function to calculate the hash of a block
    fn calculate_hash(&self) -> String {
        let input = serde_json::to_string(&self).unwrap();
        let mut hasher = SHA256::new();
        hasher.update(input.as_bytes());
        hasher.finish().as_ref().to_vec().iter().map(|&byte| format!("{:02x}", byte)).collect::<Vec<_>>().join("")
    }

    // Function to mine a new block with proof-of-work
    fn mine_block(&mut self, difficulty: usize) {
        let target = std::iter::repeat('0').take(difficulty).collect::<String>();
        while self.hash[..difficulty] != target {
            self.nonce += 1;
            self.hash = self.calculate_hash();
        }
        println!("Block mined: {}", self.hash);
    }
}

// Define Blockchain structure
#[derive(Debug)]
struct Blockchain {
    name: String,
    chain: Vec<Block>,
    difficulty: usize,
    pending_transactions: Vec<Transaction>,
    mining_reward: f64,
    key_pair: Ed25519KeyPair,
}

impl Blockchain {
    // Function to create a new blockchain with the genesis block
    fn new(name: &str, difficulty: usize, mining_reward: f64) -> Result<Self, Box<dyn Error>> {
        let genesis_block = Block {
            index: 0,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            transactions: vec![],
            previous_hash: "0".to_string(),
            hash: String::new(),
            nonce: 0,
        };
        let key_pair = Ed25519KeyPair::generate(&SystemRandom::new())?;
        let mut blockchain = Blockchain { name: name.to_string(), chain: vec![genesis_block], difficulty, pending_transactions: vec![], mining_reward, key_pair };
        blockchain.chain[0].mine_block(difficulty);
        Ok(blockchain)
    }

    // Function to add a new block to the blockchain
    fn add_block(&mut self, mut new_block: Block) {
        let previous_hash = self.chain.last().unwrap().hash.clone();
        new_block.previous_hash = previous_hash;
        new_block.mine_block(self.difficulty);
        self.chain.push(new_block);
    }

    // Function to create a new transaction
    fn create_transaction(&mut self, sender: String, recipient: String, amount: f64) -> Result<(), Box<dyn Error>> {
        let mut transaction = Transaction { sender, recipient, amount, signature: None, public_key: None };
        transaction.sign(&self.key_pair)?;
        self.pending_transactions.push(transaction);
        Ok(())
    }

    // Function to mine pending transactions and reward the miner
    fn mine_pending_transactions(&mut self, miner_address: String) {
        let reward_transaction = Transaction { sender: String::from("0"), recipient: miner_address.clone(), amount: self.mining_reward, signature: None, public_key: None };
        reward_transaction.sign(&self.key_pair).unwrap();
        self.pending_transactions.push(reward_transaction);
        
        let mut new_block = Block {
            index: self.chain.len() as u64,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            transactions: self.pending_transactions.clone(),
            previous_hash: String::new(),
            hash: String::new(),
            nonce: 0,
        };
        new_block.mine_block(self.difficulty);
        self.chain.push(new_block);

        self.pending_transactions.clear();
    }

    // Function to verify all transactions in the pending transactions pool
    fn verify_pending_transactions(&self) -> Result<(), Box<dyn Error>> {
        for transaction in &self.pending_transactions {
            transaction.verify_signature()?;
        }
        Ok(())
    }
}

// Shared state between Actix web server threads
struct AppState {
    blockchain: Arc<Mutex<Blockchain>>,
}

// Wallet balance handler
async fn wallet_balance(state: web::Data<AppState>) -> impl Responder {
    let blockchain = state.blockchain.lock().unwrap();
    let balance = blockchain.chain.iter().flat_map(|block| block.transactions.iter()).fold(0.0, |acc, tx| {
        if tx.recipient == "Miner1" { acc + tx.amount }
        else if tx.sender == "Miner1" { acc - tx.amount }
        else { acc }
    });
    HttpResponse::Ok().json(WalletBalance { balance })
}

// Create transaction handler
async fn create_transaction(payload: web::Json<TransactionPayload>, state: web::Data<AppState>) -> impl Responder {
    let mut blockchain = state.blockchain.lock().unwrap();
    match blockchain.create_transaction(payload.sender.clone(), payload.recipient.clone(), payload.amount) {
        Ok(()) => HttpResponse::Ok().finish(),
        Err(err) => HttpResponse::InternalServerError().body(err.to_string()),
    }
}

// Mine block handler
async fn mine_block(payload: web::Json<MineBlockPayload>, state: web::Data<AppState>) -> impl Responder {
    let mut blockchain = state.blockchain.lock().unwrap();
    blockchain.mine_pending_transactions(payload.miner_address.clone());
    HttpResponse::Ok().finish()
}

// Define JSON response structs
#[derive(Serialize)]
struct WalletBalance {
    balance: f64,
}

// Define request payload structs
#[derive(Deserialize)]
struct TransactionPayload {
    sender: String,
    recipient: String,
    amount: f64,
}

#[derive(Deserialize)]
struct MineBlockPayload {
    miner_address: String,
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    // Initialize blockchain
    let blockchain = Arc::new(Mutex::new(Blockchain::new("TMHP", 4, 10.0).unwrap()));

    // Start Actix web server
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(AppState {
                blockchain: blockchain.clone(),
            }))
            .route("/wallet-balance", web::get().to(wallet_balance))
            .route("/create-transaction", web::post().to(create_transaction))
            .route("/mine-block", web::post().to(mine_block))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
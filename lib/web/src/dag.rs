use anyhow::Result;
use libipld::{cbor::DagCborCodec, codec::Codec, Ipld};
use wasm_bindgen::prelude::*;
use js_sys;
use serde_wasm_bindgen::{from_value, Serializer};
use serde::Serialize;
use std::io::Write;
use unsigned_varint::encode as varint_encode;

const ENC_BLOCK_SIZE: usize = 24;
const IDENTITY_CODE: u64 = 0x00;
const DAG_CBOR_CODE: u64 = 0x71;
const VERSION_1: u64 = 0x01;

#[derive(Debug)]
struct SimpleCid {
    codec: u64,
    digest: Vec<u8>,
}

impl SimpleCid {
    fn new_v1(codec: u64, digest: Vec<u8>) -> Self {
        Self { codec, digest }
    }

    fn write_bytes<W: Write>(&self, mut w: W) -> Result<usize> {
        let mut version_buf = varint_encode::u64_buffer();
        let version = varint_encode::u64(VERSION_1, &mut version_buf);

        let mut codec_buf = varint_encode::u64_buffer();
        let codec = varint_encode::u64(self.codec, &mut codec_buf);

        let mut hash_code_buf = varint_encode::u64_buffer();
        let hash_code = varint_encode::u64(IDENTITY_CODE, &mut hash_code_buf);

        let mut size_buf = varint_encode::u64_buffer();
        let size = varint_encode::u64(self.digest.len() as u64, &mut size_buf);

        let mut written = 0;
        written += w.write(version)?;
        written += w.write(codec)?;
        written += w.write(hash_code)?;
        written += w.write(size)?;
        written += w.write(&self.digest)?;

        Ok(written)
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.write_bytes(&mut bytes).unwrap();
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use unsigned_varint::decode as varint;

        // Read version
        let (version, rest) = varint::u64(&bytes)?;
        if version != VERSION_1 {
            anyhow::bail!("Only CIDv1 is supported");
        }

        // Read codec
        let (codec, rest) = varint::u64(rest)?;

        // Read hash code
        let (hash_code, rest) = varint::u64(rest)?;
        if hash_code != IDENTITY_CODE {
            anyhow::bail!("Only identity hash is supported");
        }

        // Read hash length
        let (hash_len, rest) = varint::u64(rest)?;

        // Read digest
        let digest = rest[..hash_len as usize].to_vec();

        Ok(Self::new_v1(codec, digest))
    }
}

fn pad(bytes: &[u8], block_size: Option<usize>) -> Vec<u8> {
    let block_size = block_size.unwrap_or(ENC_BLOCK_SIZE);
    let pad_len = (block_size - (bytes.len() % block_size)) % block_size;
    let mut padded = Vec::with_capacity(bytes.len() + pad_len);
    padded.extend_from_slice(bytes);
    padded.extend(std::iter::repeat(0).take(pad_len));
    padded
}

/// Converts a JavaScript value to IPLD with fallback handling
fn js_value_to_ipld(value: &JsValue) -> Result<Ipld> {
    // First try the standard serde-wasm-bindgen conversion
    match from_value(value.clone()) {
        Ok(ipld) => Ok(ipld),
        Err(_) => {
            // If that fails, handle common edge cases
            if value.is_null() || value.is_undefined() {
                Ok(Ipld::Null)
            } else if let Some(s) = value.as_string() {
                Ok(Ipld::String(s))
            } else if let Some(b) = value.as_bool() {
                Ok(Ipld::Bool(b))
            } else if let Some(n) = value.as_f64() {
                if n.fract() == 0.0 {
                    Ok(Ipld::Integer(n as i128))
                } else {
                    Ok(Ipld::Float(n))
                }
            } else {
                // Try to handle objects and arrays manually
                if js_sys::Array::is_array(value) {
                    let array = js_sys::Array::from(value);
                    let mut ipld_list = Vec::new();
                    for i in 0..array.length() {
                        let item = array.get(i);
                        ipld_list.push(js_value_to_ipld(&item)?);
                    }
                    Ok(Ipld::List(ipld_list))
                } else {
                    // Try to handle as object
                    let obj = js_sys::Object::from(value.clone());
                    let keys = js_sys::Object::keys(&obj);
                    let mut ipld_map = std::collections::BTreeMap::new();
                    
                    for i in 0..keys.length() {
                        let key = keys.get(i);
                        if let Some(key_str) = key.as_string() {
                            if let Ok(prop_value) = js_sys::Reflect::get(&obj, &key) {
                                if !prop_value.is_undefined() {
                                    ipld_map.insert(key_str, js_value_to_ipld(&prop_value)?);
                                }
                            }
                        }
                    }
                    Ok(Ipld::Map(ipld_map))
                }
            }
        }
    }
}

/// Encodes a value using DAG-CBOR and creates a CID with identity multihash
fn encode_identity_cid(value: &JsValue) -> Result<SimpleCid> {
    let ipld = js_value_to_ipld(value)?;
    let bytes = DagCborCodec.encode(&ipld)?;
    Ok(SimpleCid::new_v1(DAG_CBOR_CODE, bytes))
}

/// Converts IPLD back to JavaScript value, handling edge cases
fn ipld_to_js_value(ipld: &Ipld) -> Result<JsValue> {
    match ipld {
        Ipld::Null => Ok(JsValue::NULL),
        Ipld::Bool(b) => Ok(JsValue::from(*b)),
        Ipld::Integer(i) => Ok(JsValue::from(*i as f64)),
        Ipld::Float(f) => Ok(JsValue::from(*f)),
        Ipld::String(s) => Ok(JsValue::from_str(s)),
        Ipld::Bytes(bytes) => {
            let uint8_array = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
            uint8_array.copy_from(bytes);
            Ok(uint8_array.into())
        }
        Ipld::List(list) => {
            let js_array = js_sys::Array::new();
            for item in list.iter() {
                let js_item = ipld_to_js_value(item)?;
                js_array.push(&js_item);
            }
            Ok(js_array.into())
        }
        Ipld::Map(map) => {
            let js_obj = js_sys::Object::new();
            for (key, value) in map {
                let js_key = JsValue::from_str(key);
                let js_value = ipld_to_js_value(value)?;
                js_sys::Reflect::set(&js_obj, &js_key, &js_value)
                    .map_err(|_| anyhow::anyhow!("Failed to set property '{}' on JS object", key))?;
            }
            Ok(js_obj.into())
        }
        Ipld::Link(_) => {
            let serializer = Serializer::json_compatible();
            ipld.serialize(&serializer)
                .map_err(|e| anyhow::anyhow!("Failed to serialize IPLD link: {}", e))
        }
    }
}

/// Decodes a CID with identity multihash back to the original value
fn decode_identity_cid(cid: &SimpleCid) -> Result<JsValue> {
    if cid.codec != DAG_CBOR_CODE {
        anyhow::bail!("CID codec must be dag-cbor");
    }
    
    let ipld: Ipld = DagCborCodec.decode(&cid.digest)?;
    ipld_to_js_value(&ipld)
}

/// Prepares cleartext for encryption by encoding it as a CID and padding
pub async fn prepare_cleartext(cleartext: &JsValue, block_size: Option<usize>) -> Result<Vec<u8>> {
    let cid = encode_identity_cid(cleartext)?;
    Ok(pad(&cid.to_bytes(), block_size))
}

/// Decodes padded cleartext bytes back to the original value
pub fn decode_cleartext(bytes: &[u8]) -> Result<JsValue> {
    let cid = SimpleCid::from_bytes(bytes)?;
    decode_identity_cid(&cid)
}

use super::ProxyStream;
use crate::common::{
    hash, parse_port, parse_addr, KDFSALT_CONST_AEAD_RESP_HEADER_IV, KDFSALT_CONST_AEAD_RESP_HEADER_KEY, KDFSALT_CONST_AEAD_RESP_HEADER_LEN_IV, KDFSALT_CONST_AEAD_RESP_HEADER_LEN_KEY, KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY, KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY
};
use std::io::Cursor;
use aes::cipher::KeyInit;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm,
};
use md5::{Digest, Md5};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::*;
use uuid::Uuid;

struct VmessCommand {
    is_tcp: bool,
    remote_port: u16,
    remote_addr: String,
    key: [u8; 16],
    iv: [u8; 16],
    options: [u8; 4],
}


impl <'a> ProxyStream<'a> {
    async fn aead_decrypt(&mut self) -> Result<Vec<u8>> {
        // +-------------------+-------------------+-------------------+
        // |     Auth ID       |   Header Length   |       Nonce       |
        // +-------------------+-------------------+-------------------+
        // |     16 Bytes      |     18 Bytes      |      8 Bytes      |
        // +-------------------+-------------------+-------------------+
        let mut auth_id = [0u8; 16];
        self.read_exact(&mut auth_id).await?;
        let mut len_buf = [0u8; 18];
        self.read_exact(&mut len_buf).await?;
        let mut nonce = [0u8; 8];
        self.read_exact(&mut nonce).await?;

        let mut key: Option<[u8; 16]> = None;
        let mut header_length: u16 = 0;

        for uuid in &self.config.uuid {
            let p_key = crate::md5!(uuid.as_bytes());

            // https://github.com/v2fly/v2ray-core/blob/master/proxy/vmess/aead/kdf.go
            let header_length_key = &hash::kdf(
                &p_key,
                &[
                    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                    &auth_id,
                    &nonce,
                ],
            )[..16];

            let header_length_nonce = &hash::kdf(
                &p_key,
                &[
                    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
                    &auth_id,
                    &nonce,
                ],
            )[..12];

            let payload = Payload {
                msg: &len_buf,
                aad: &auth_id,
            };

            if let Ok(len) = Aes128Gcm::new(header_length_key.into())
                .decrypt(header_length_nonce.into(), payload) {
                header_length = ((len[0] as u16) << 8) | (len[1] as u16);
                key = Some(p_key.into());
                break;
            }
        }

        let key = key.ok_or(Error::RustError("can not find available uuid".to_string()))?;

        // 16 bytes padding
        let mut cmd = vec![0u8; (header_length + 16) as _];
        self.read_exact(&mut cmd).await?;

        let header_payload = {
            let payload_key = &hash::kdf(
                &key,
                &[
                    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
                    &auth_id,
                    &nonce,
                ],
            )[..16];
            let payload_nonce = &hash::kdf(
                &key,
                &[KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, &auth_id, &nonce],
            )[..12];

            let payload = Payload {
                msg: &cmd,
                aad: &auth_id,
            };

            Aes128Gcm::new(payload_key.into())
                .decrypt(payload_nonce.into(), payload)
                .map_err(|e| Error::RustError(e.to_string()))?
        };

        Ok(header_payload)
    }

    async fn parse_vmess_command(&mut self, p: Vec<u8>) -> Result<VmessCommand> {
        let mut buf = Cursor::new(p);

        // https://xtls.github.io/en/development/protocols/vmess.html#command-section
        //
        // +---------+--------------------+---------------------+-------------------------------+---------+----------+-------------------+----------+---------+---------+--------------+---------+--------------+----------+
        // | 1 Byte  |      16 Bytes      |      16 Bytes       |            1 Byte             | 1 Byte  |  4 bits  |      4 bits       |  1 Byte  | 1 Byte  | 2 Bytes |    1 Byte    | N Bytes |   P Bytes    | 4 Bytes  |
        // +---------+--------------------+---------------------+-------------------------------+---------+----------+-------------------+----------+---------+---------+--------------+---------+--------------+----------+
        // | Version | Data Encryption IV | Data Encryption Key | Response Authentication Value | Options | Reserved | Encryption Method | Reserved | Command | Port    | Address Type | Address | Random Value | Checksum |
        // +---------+--------------------+---------------------+-------------------------------+---------+----------+-------------------+----------+---------+---------+--------------+---------+--------------+----------+

        let version = buf.read_u8().await?;
        if version != 1 {
            return Err(Error::RustError("invalid version".to_string()));
        }

        let mut iv = [0u8; 16];
        buf.read_exact(&mut iv).await?;
        let mut key = [0u8; 16];
        buf.read_exact(&mut key).await?;

        // ignore options for now
        let mut options = [0u8; 4];
        buf.read_exact(&mut options).await?;

        let cmd = buf.read_u8().await?;
        let is_tcp = cmd == 0x1;

        let remote_port = parse_port(&mut buf).await?;
        let remote_addr = parse_addr(&mut buf).await?;

        Ok(VmessCommand {
            is_tcp,
            remote_port,
            remote_addr,
            key,
            iv,
            options,
        })
    }

    pub async fn process_vmess(&mut self) -> Result<()> {
        let p = self.aead_decrypt().await?;
        let cmd = self.parse_vmess_command(p).await?;

        // encrypt payload
        let key = &crate::sha256!(&cmd.key)[..16];
        let iv = &crate::sha256!(&cmd.iv)[..12];

        // https://github.com/v2ray/v2ray-core/blob/master/proxy/vmess/encoding/client.go#L196
        let length_key = &hash::kdf(&key, &[KDFSALT_CONST_AEAD_RESP_HEADER_LEN_KEY])[..16];
        let length_iv = &hash::kdf(&iv, &[KDFSALT_CONST_AEAD_RESP_HEADER_LEN_IV])[..12];
        let length = Aes128Gcm::new(length_key.into())
            // 4 bytes header: https://github.com/v2ray/v2ray-core/blob/master/proxy/vmess/encoding/client.go#L238
            .encrypt(length_iv.into(), &4u16.to_be_bytes()[..])
            .map_err(|e| Error::RustError(e.to_string()))?;
        self.write(&length).await?;

        let payload_key = &hash::kdf(&key, &[KDFSALT_CONST_AEAD_RESP_HEADER_KEY])[..16];
        let payload_iv = &hash::kdf(&iv, &[KDFSALT_CONST_AEAD_RESP_HEADER_IV])[..12];
        let header = {
            let header = [
                cmd.options[0], // https://github.com/v2ray/v2ray-core/blob/master/proxy/vmess/encoding/client.go#L242
                0x00, 0x00, 0x00,
            ];
            Aes128Gcm::new(payload_key.into())
                .encrypt(payload_iv.into(), &header[..])
                .map_err(|e| Error::RustError(e.to_string()))?
        };
        self.write(&header).await?;

        if cmd.is_tcp {
            let addr_pool = [
                (cmd.remote_addr.clone(), cmd.remote_port),
                (self.config.proxy_addr.clone(), self.config.proxy_port)
            ];

            for (target_addr, target_port) in addr_pool {
                if let Err(e) = self.handle_tcp_outbound(target_addr, target_port).await {
                    console_error!("error handling tcp: {}", e)
                }
            }
        } else {
            if let Err(e) = self.handle_udp_outbound().await {
                console_error!("error handling udp: {}", e)
            }
        }

        Ok(())
    }
}

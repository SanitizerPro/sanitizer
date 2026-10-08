use evtx::{
EvtxChunk,
EvtxChunkHeader,
EvtxParser,
ParserSettings,
};
use js_sys::Uint8Array;
use std::io::Cursor;
use wasm_bindgen::prelude::*;

const FILE_HEADER_SIZE: usize = 4096;
const CHUNK_SIZE: usize = 65536;

#[wasm_bindgen(start)]
pub fn initialize() {
console_error_panic_hook::set_once();
}

fn parser_settings() -> ParserSettings {
ParserSettings::default()
.num_threads(1)
.indent(false)
.validate_checksums(true)
}

#[wasm_bindgen]
pub struct EvtxWasmParser {
data: Vec<u8>,
chunk_offsets: Vec<usize>,
}

impl EvtxWasmParser {
fn from_data(
data: Vec<u8>
) -> Result<Self, String> {
if data.len() < FILE_HEADER_SIZE {
return Err(
"Invalid EVTX file: incomplete file header."
.to_string()
);
}


    EvtxParser::from_read_seek(
        Cursor::new(&data)
    )
    .map_err(|error| {
        format!(
            "Invalid EVTX file: {error}"
        )
    })?;

    let chunks =
        data.get(FILE_HEADER_SIZE..)
            .ok_or_else(|| {
                "Invalid EVTX file header."
                    .to_string()
            })?;

    let chunk_offsets =
        chunks
            .chunks(CHUNK_SIZE)
            .enumerate()
            .filter(|(_, bytes)| {
                bytes.iter()
                    .any(|byte| *byte != 0)
            })
            .map(|(index, _)| {
                FILE_HEADER_SIZE +
                    index * CHUNK_SIZE
            })
            .collect::<Vec<_>>();

    if chunk_offsets.is_empty() {
        return Err(
            "Invalid EVTX file: no event-log chunks were found."
                .to_string()
        );
    }

    Ok(Self {
        data,
        chunk_offsets
    })
}

fn get_chunk(
    &self,
    index: usize
) -> Result<
    (&[u8], EvtxChunkHeader),
    String
> {
    let offset =
        *self.chunk_offsets
            .get(index)
            .ok_or_else(|| {
                format!(
                    "EVTX chunk index {index} is out of range."
                )
            })?;

    let end =
        self.data
            .len()
            .min(
                offset + CHUNK_SIZE
            );

    let bytes =
        &self.data[offset..end];

    if bytes.len() != CHUNK_SIZE {
        return Err(format!(
            "EVTX chunk {index} is incomplete: {} bytes.",
            bytes.len()
        ));
    }

    let header =
        EvtxChunkHeader::from_bytes(
            bytes
        )
        .map_err(|error| {
            format!(
                "EVTX chunk {index} header is invalid: {error}"
            )
        })?;

    Ok((bytes, header))
}


}

#[wasm_bindgen]
impl EvtxWasmParser {
#[wasm_bindgen(constructor)]
pub fn new(
data: Vec<u8>
) -> Result<
EvtxWasmParser,
JsError
> {
Self::from_data(data)
.map_err(|error| {
JsError::new(&error)
})
}


#[wasm_bindgen(getter)]
pub fn total_chunks(
    &self
) -> usize {
    self.chunk_offsets.len()
}

pub fn chunk_xml(
    &self,
    chunk_index: usize
) -> Result<
    Uint8Array,
    JsError
> {
    let (
        bytes,
        header
    ) =
        self.get_chunk(
            chunk_index
        )
        .map_err(|error| {
            JsError::new(&error)
        })?;

    let mut chunk =
        EvtxChunk::new(
            bytes,
            &header,
            std::sync::Arc::new(
                parser_settings()
            )
        )
        .map_err(|error| {
            JsError::new(
                &error.to_string()
            )
        })?;

    let mut output =
        Vec::<u8>::new();

    for record in
        chunk.iter()
    {
        let record =
            record.map_err(
                |error| {
                    JsError::new(
                        &format!(
                            "EVTX record parsing failed in chunk {}: {}",
                            chunk_index,
                            error
                        )
                    )
                }
            )?;

        let xml =
            record
                .into_xml_bytes()
                .map_err(
                    |error| {
                        JsError::new(
                            &format!(
                                "EVTX XML rendering failed in chunk {}: {}",
                                chunk_index,
                                error
                            )
                        )
                    }
                )?;

        output.extend_from_slice(
            &xml.data
        );

        output.push(
            b'\n'
        );
    }

    Ok(
        Uint8Array::from(
            &output[..]
        )
    )
}


}

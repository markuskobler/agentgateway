use crate::llm::AIError;
use crate::llm::types::{completions, responses};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

pub fn translate_responses_request(req: &responses::Request) -> Result<Vec<u8>, AIError> {
	let mut messages = Vec::new();

	if let Some(instructions) = req
		.instructions
		.as_deref()
		.filter(|text| !text.trim().is_empty())
	{
		messages.push(text_message("developer", instructions.to_owned()));
	}

	match &req.input {
		responses::RequestInput::Text(text) => {
			messages.push(text_message("user", text.clone()));
		},
		responses::RequestInput::Items(items) => {
			for item in items {
				let value = serde_json::to_value(item).map_err(AIError::RequestMarshal)?;
				if let Some(message) = translate_input_item(&value) {
					push_message(&mut messages, message);
				}
			}
		},
	}

	warn_unsupported_request_fields(&req.rest, req.reasoning.as_ref());

	let translated = completions::Request {
		messages,
		model: req.model.clone(),
		top_p: req.top_p,
		temperature: req.temperature,
		stream: req.stream,
		stream_options: stream_options(req.stream),
		max_completion_tokens: req.max_output_tokens,
		tools: translate_tools(req.tools.as_deref()),
		tool_choice: translate_tool_choice(req.tool_choice.as_ref()),
		rest: Value::Object(to_completion_extra(req)),
		stop: None,
		max_tokens: None,
		user: None,
		frequency_penalty: None,
		presence_penalty: None,
		seed: None,
	};

	serde_json::to_vec(&translated).map_err(AIError::RequestMarshal)
}

fn to_completion_extra(req: &responses::Request) -> Map<String, Value> {
	let mut extra = Map::new();

	if let Some(response_format) = translate_response_format(req.text.as_ref()) {
		extra.insert("response_format".to_string(), response_format);
	}
	if let Some(verbosity) = text_verbosity(req.text.as_ref()) {
		extra.insert("verbosity".to_string(), verbosity);
	}
	if let Some(reasoning_effort) = translate_reasoning_effort(req.reasoning.as_ref()) {
		extra.insert("reasoning_effort".to_string(), reasoning_effort);
	}
	if let Some(parallel_tool_calls) = req.parallel_tool_calls {
		extra.insert(
			"parallel_tool_calls".to_string(),
			Value::Bool(parallel_tool_calls),
		);
	}
	if let Some(metadata) = &req.metadata
		&& let Ok(metadata) = serde_json::to_value(metadata)
	{
		extra.insert("metadata".to_string(), metadata);
	}
	if let Some(service_tier) = &req.service_tier
		&& let Ok(service_tier) = serde_json::to_value(service_tier)
	{
		extra.insert("service_tier".to_string(), service_tier);
	}
	if let Some(store) = req.store {
		extra.insert("store".to_string(), Value::Bool(store));
	}
	if let Some(user) = user_identifier(req) {
		extra.insert("user".to_string(), user);
	}

	extra
}

fn user_identifier(req: &responses::Request) -> Option<Value> {
	req
		.user
		.as_ref()
		.map(|user| Value::String(user.clone()))
		.or_else(|| {
			req
				.safety_identifier
				.as_ref()
				.map(|id| Value::String(id.clone()))
		})
}

fn text_verbosity(text: Option<&responses::RawTextParam>) -> Option<Value> {
	text?.as_value().get("verbosity").cloned()
}

fn warn_unsupported_request_fields(rest: &Value, reasoning: Option<&responses::RawReasoningParam>) {
	for unsupported in [
		"background",
		"conversation",
		"include",
		"max_tool_calls",
		"previous_response_id",
		"prompt",
		"prompt_cache_key",
		"prompt_cache_retention",
		"truncation",
	] {
		if rest.get(unsupported).is_some() {
			tracing::warn!(
				field = unsupported,
				"responses field is not supported in Gemini chat-completions conversion"
			);
		}
	}

	if reasoning
		.and_then(|reasoning| reasoning.as_value().get("generate_summary"))
		.is_some()
	{
		tracing::warn!(
			field = "reasoning.generate_summary",
			"responses field is not supported in Gemini chat-completions conversion"
		);
	}
	if reasoning
		.and_then(|reasoning| reasoning.as_value().get("summary"))
		.is_some()
	{
		tracing::warn!(
			field = "reasoning.summary",
			"responses field is not supported in Gemini chat-completions conversion"
		);
	}
}

#[derive(Debug, Deserialize)]
struct ResponsesMessageItem {
	role: String,
	content: ResponsesInputContent,
}

#[derive(Debug, Deserialize)]
struct ResponsesFunctionCallItem {
	call_id: String,
	name: String,
	#[serde(default)]
	arguments: String,
}

#[derive(Debug, Deserialize)]
struct ResponsesFunctionCallOutputItem {
	call_id: String,
	#[serde(default)]
	output: ResponsesInputContent,
}

#[derive(Debug, Deserialize)]
struct ResponsesCustomToolCallItem {
	call_id: String,
	name: String,
	#[serde(default)]
	input: String,
}

#[derive(Debug, Deserialize)]
struct ResponsesCustomToolCallOutputItem {
	call_id: String,
	#[serde(default)]
	output: ResponsesInputContent,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ResponsesInputContent {
	Text(String),
	Parts(Vec<ResponsesContentPart>),
	Other { _raw: Value },
}

impl Default for ResponsesInputContent {
	fn default() -> Self {
		Self::Other { _raw: Value::Null }
	}
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ResponsesContentPart {
	Typed(ResponsesKnownContentPart),
	Other { _raw: Value },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ResponsesKnownContentPart {
	InputText {
		text: String,
	},
	OutputText {
		text: String,
	},
	Refusal {
		#[serde(default)]
		text: Option<String>,
		#[serde(default)]
		refusal: Option<String>,
	},
	InputImage {
		#[serde(default)]
		image_url: Option<String>,
		#[serde(default)]
		detail: Option<Value>,
	},
	InputFile {
		#[serde(default)]
		file_data: Option<Value>,
		#[serde(default)]
		file_id: Option<Value>,
		#[serde(default)]
		filename: Option<Value>,
	},
}

#[derive(Default)]
struct AssistantPayload {
	content: Option<completions::Content>,
	refusal: Option<String>,
}

impl ResponsesInputContent {
	fn into_user_content(self) -> Option<completions::Content> {
		match self {
			Self::Text(text) => Some(completions::Content::Text(text)),
			Self::Parts(parts) => {
				let parts = parts
					.into_iter()
					.filter_map(ResponsesContentPart::into_user_content_part)
					.collect::<Vec<_>>();
				if parts.is_empty() {
					None
				} else {
					Some(completions::Content::Array(parts))
				}
			},
			Self::Other { .. } => None,
		}
	}

	fn into_text(self) -> Option<String> {
		match self {
			Self::Text(text) => Some(text),
			Self::Parts(parts) => join_non_empty(
				parts
					.iter()
					.filter_map(ResponsesContentPart::text)
					.map(ToOwned::to_owned),
			),
			Self::Other { .. } => None,
		}
	}

	fn into_text_or_default(self) -> String {
		self.into_text().unwrap_or_default()
	}

	fn into_assistant_payload(self) -> AssistantPayload {
		match self {
			Self::Text(text) => AssistantPayload {
				content: Some(completions::Content::Text(text)),
				refusal: None,
			},
			Self::Parts(parts) => AssistantPayload {
				content: join_non_empty(
					parts
						.iter()
						.filter_map(ResponsesContentPart::text)
						.map(ToOwned::to_owned),
				)
				.map(completions::Content::Text),
				refusal: join_non_empty(
					parts
						.iter()
						.filter_map(ResponsesContentPart::refusal)
						.map(ToOwned::to_owned),
				),
			},
			Self::Other { .. } => AssistantPayload::default(),
		}
	}
}

impl ResponsesContentPart {
	fn text(&self) -> Option<&str> {
		match self {
			Self::Typed(part) => part.text(),
			Self::Other { .. } => None,
		}
	}

	fn refusal(&self) -> Option<&str> {
		match self {
			Self::Typed(part) => part.refusal(),
			Self::Other { .. } => None,
		}
	}

	fn into_user_content_part(self) -> Option<completions::ContentPart> {
		match self {
			Self::Typed(part) => part.into_user_content_part(),
			Self::Other { .. } => None,
		}
	}
}

impl ResponsesKnownContentPart {
	fn text(&self) -> Option<&str> {
		match self {
			Self::InputText { text } | Self::OutputText { text } => Some(text),
			_ => None,
		}
	}

	fn refusal(&self) -> Option<&str> {
		match self {
			Self::Refusal { text, refusal } => text.as_deref().or(refusal.as_deref()),
			_ => None,
		}
	}

	fn into_user_content_part(self) -> Option<completions::ContentPart> {
		match self {
			Self::InputText { text } | Self::OutputText { text } => Some(text_content_part(text)),
			Self::InputImage {
				image_url: Some(image_url),
				detail,
			} => Some(image_content_part(image_url, detail)),
			Self::InputImage {
				image_url: None, ..
			} => {
				tracing::warn!("dropping responses input_image without image_url for Gemini conversion");
				None
			},
			Self::InputFile {
				file_data,
				file_id,
				filename,
			} => file_content_part(file_data, file_id, filename),
			Self::Refusal { .. } => None,
		}
	}
}

fn stream_options(stream: Option<bool>) -> Option<completions::StreamOptions> {
	stream
		.filter(|stream| *stream)
		.map(|_| completions::StreamOptions {
			include_usage: true,
			rest: Value::Object(Map::new()),
		})
}

fn text_message(role: &str, text: String) -> completions::RequestMessage {
	completions::RequestMessage {
		role: role.to_string(),
		name: None,
		content: Some(completions::Content::Text(text)),
		tool_call_id: None,
		tool_calls: None,
		rest: Value::Object(Map::new()),
	}
}

fn request_message(role: &str) -> completions::RequestMessage {
	completions::RequestMessage {
		role: role.to_string(),
		name: None,
		content: None,
		tool_call_id: None,
		tool_calls: None,
		rest: Value::Object(Map::new()),
	}
}

fn text_content_part(text: String) -> completions::ContentPart {
	completions::ContentPart {
		r#type: "text".to_string(),
		text: Some(text),
		rest: Value::Object(Map::new()),
	}
}

fn image_content_part(image_url: String, detail: Option<Value>) -> completions::ContentPart {
	let mut image = Map::new();
	image.insert("url".to_string(), Value::String(image_url));
	if let Some(detail) = detail {
		image.insert("detail".to_string(), detail);
	}

	let mut rest = Map::new();
	rest.insert("image_url".to_string(), Value::Object(image));
	completions::ContentPart {
		r#type: "image_url".to_string(),
		text: None,
		rest: Value::Object(rest),
	}
}

fn file_content_part(
	file_data: Option<Value>,
	file_id: Option<Value>,
	filename: Option<Value>,
) -> Option<completions::ContentPart> {
	let mut file = Map::new();
	if let Some(file_data) = file_data {
		file.insert("file_data".to_string(), file_data);
	}
	if let Some(file_id) = file_id {
		file.insert("file_id".to_string(), file_id);
	}
	if let Some(filename) = filename {
		file.insert("filename".to_string(), filename);
	}
	if file.is_empty() {
		tracing::warn!(
			"dropping responses input_file without chat-completions-compatible fields for Gemini conversion"
		);
		return None;
	}

	let mut rest = Map::new();
	rest.insert("file".to_string(), Value::Object(file));
	Some(completions::ContentPart {
		r#type: "file".to_string(),
		text: None,
		rest: Value::Object(rest),
	})
}

fn assistant_tool_call_message(tool_call: Value) -> completions::RequestMessage {
	let mut message = request_message("assistant");
	message.tool_calls = Some(vec![tool_call]);
	message
}

fn tool_output_message(call_id: String, output: String) -> completions::RequestMessage {
	let mut message = request_message("tool");
	message.content = Some(completions::Content::Text(output));
	message.tool_call_id = Some(call_id);
	message
}

fn translate_input_item(item: &Value) -> Option<completions::RequestMessage> {
	match item.get("type").and_then(Value::as_str) {
		Some("function_call") => parse_value::<ResponsesFunctionCallItem>(item, "input.function_call")
			.map(|call| {
				assistant_tool_call_message(json!({
					"id": call.call_id,
					"type": "function",
					"function": {
						"name": call.name,
						"arguments": call.arguments,
					}
				}))
			}),
		Some("function_call_output") => {
			parse_value::<ResponsesFunctionCallOutputItem>(item, "input.function_call_output")
				.map(|output| tool_output_message(output.call_id, output.output.into_text_or_default()))
		},
		Some("custom_tool_call") => {
			parse_value::<ResponsesCustomToolCallItem>(item, "input.custom_tool_call").map(|call| {
				assistant_tool_call_message(json!({
					"id": call.call_id,
					"type": "custom",
					"custom_tool": {
						"name": call.name,
						"input": call.input,
					}
				}))
			})
		},
		Some("custom_tool_call_output") => {
			parse_value::<ResponsesCustomToolCallOutputItem>(item, "input.custom_tool_call_output")
				.map(|output| tool_output_message(output.call_id, output.output.into_text_or_default()))
		},
		Some("message") | None if item.get("role").is_some() => {
			parse_value::<ResponsesMessageItem>(item, "input.message").and_then(translate_message_item)
		},
		Some("item_reference") => None,
		Some(other) => {
			tracing::warn!(
				item_type = other,
				"dropping unsupported responses input item for Gemini conversion"
			);
			None
		},
		None => None,
	}
}

fn translate_message_item(item: ResponsesMessageItem) -> Option<completions::RequestMessage> {
	match item.role.as_str() {
		"user" => {
			let mut message = request_message("user");
			message.content = item.content.into_user_content();
			Some(message)
		},
		"system" | "developer" => {
			let mut message = request_message(&item.role);
			message.content = item.content.into_text().map(completions::Content::Text);
			Some(message)
		},
		"assistant" => {
			let payload = item.content.into_assistant_payload();
			let mut message = request_message("assistant");
			message.content = payload.content;
			if let Some(refusal) = payload.refusal {
				message.rest = Value::Object(Map::from_iter([(
					"refusal".to_string(),
					Value::String(refusal),
				)]));
			}
			Some(message)
		},
		_ => None,
	}
}

fn push_message(
	messages: &mut Vec<completions::RequestMessage>,
	message: completions::RequestMessage,
) {
	if message.role == "assistant"
		&& message.content.is_none()
		&& let Some(tool_calls) = &message.tool_calls
		&& !tool_calls.is_empty()
		&& let Some(last) = messages.last_mut()
		&& last.role == "assistant"
		&& last.content.is_none()
	{
		last
			.tool_calls
			.get_or_insert_default()
			.extend(tool_calls.clone());
		return;
	}
	messages.push(message);
}

fn parse_value<T: DeserializeOwned>(value: &Value, field: &str) -> Option<T> {
	match serde_json::from_value::<T>(value.clone()) {
		Ok(parsed) => Some(parsed),
		Err(err) => {
			tracing::warn!(field, %err, "dropping malformed responses payload for Gemini conversion");
			None
		},
	}
}

fn join_non_empty(parts: impl Iterator<Item = String>) -> Option<String> {
	let joined = parts
		.filter(|text| !text.is_empty())
		.collect::<Vec<_>>()
		.join("\n");
	if joined.is_empty() {
		None
	} else {
		Some(joined)
	}
}

fn translate_tools(tools: Option<&[responses::RawTool]>) -> Option<Vec<Value>> {
	let translated = tools?
		.iter()
		.filter_map(|tool| {
			let tool_type = tool
				.as_value()
				.get("type")
				.and_then(Value::as_str)
				.unwrap_or("unknown");
			let tool = parse_value::<responses::typed::Tool>(tool.as_value(), "tools[]")?;
			match tool {
				responses::typed::Tool::Function(function) => Some(json!({
					"type": "function",
					"function": {
						"name": function.name,
						"description": function.description,
						"parameters": function.parameters,
						"strict": function.strict,
					}
				})),
				_ => {
					tracing::warn!(
						tool_type,
						"dropping unsupported responses tool for Gemini conversion"
					);
					None
				},
			}
		})
		.collect::<Vec<_>>();

	if translated.is_empty() {
		None
	} else {
		Some(translated)
	}
}

fn translate_tool_choice(value: Option<&responses::RawToolChoice>) -> Option<Value> {
	let tool_choice =
		parse_value::<responses::typed::ToolChoiceParam>(value?.as_value(), "tool_choice")?;
	match tool_choice {
		responses::typed::ToolChoiceParam::Mode(mode) => serde_json::to_value(mode).ok(),
		responses::typed::ToolChoiceParam::Function(function) => Some(json!({
			"type": "function",
			"function": { "name": function.name }
		})),
		other => {
			tracing::warn!(
				tool_choice = ?other,
				"dropping unsupported responses tool_choice for Gemini conversion"
			);
			None
		},
	}
}

fn translate_response_format(text: Option<&responses::RawTextParam>) -> Option<Value> {
	let format = text?.as_value().get("format")?;
	let format =
		parse_value::<responses::typed::TextResponseFormatConfiguration>(format, "text.format")?;
	match format {
		responses::typed::TextResponseFormatConfiguration::Text => None,
		responses::typed::TextResponseFormatConfiguration::JsonObject => {
			Some(json!({ "type": "json_object" }))
		},
		responses::typed::TextResponseFormatConfiguration::JsonSchema(json_schema) => {
			let mut formatted_schema = Map::new();
			formatted_schema.insert("name".to_string(), Value::String(json_schema.name));
			if let Some(description) = json_schema.description {
				formatted_schema.insert("description".to_string(), Value::String(description));
			}
			if let Some(schema) = json_schema.schema {
				formatted_schema.insert("schema".to_string(), schema);
			}
			if let Some(strict) = json_schema.strict {
				formatted_schema.insert("strict".to_string(), Value::Bool(strict));
			}
			Some(json!({
				"type": "json_schema",
				"json_schema": Value::Object(formatted_schema),
			}))
		},
	}
}

fn translate_reasoning_effort(reasoning: Option<&responses::RawReasoningParam>) -> Option<Value> {
	let reasoning = parse_value::<responses::typed::Reasoning>(reasoning?.as_value(), "reasoning")?;
	reasoning
		.effort
		.and_then(|effort| serde_json::to_value(effort).ok())
}

pub mod from_completions {
	use std::collections::BTreeMap;
	use std::time::Instant;

	use agent_core::strng;
	use async_openai::types::responses::RefusalContent;
	use bytes::Bytes;
	use rand::RngExt;
	use serde::Deserialize;
	use serde_json::Value;
	use tiktoken_rs::tokenizer::{Tokenizer, get_tokenizer};

	use crate::llm::types::ResponseType;
	use crate::llm::types::{completions, responses};
	use crate::llm::{AIError, AmendOnDrop, types};
	use crate::parse;
	use crate::parse::sse::SseJsonEvent;

	use crate::http::Body;

	#[derive(Debug, Default)]
	struct GeminiStreamChunk {
		id: String,
		model: String,
		service_tier: Option<String>,
		choices: Vec<GeminiStreamChoice>,
		usage: Option<completions::typed::Usage>,
	}

	#[derive(Debug, Default)]
	struct GeminiStreamChoice {
		delta: GeminiStreamDelta,
		finish_reason: Option<String>,
	}

	#[derive(Debug, Default)]
	struct GeminiStreamDelta {
		content: Option<String>,
		reasoning_content: Option<String>,
		tool_calls: Option<Vec<GeminiToolCallChunk>>,
	}

	#[derive(Debug, Default)]
	struct GeminiToolCallChunk {
		index: u32,
		id: Option<String>,
		function: Option<GeminiFunctionCallStream>,
	}

	#[derive(Debug, Default)]
	struct GeminiFunctionCallStream {
		name: Option<String>,
		arguments: Option<String>,
	}

	#[derive(Debug, Default, Deserialize)]
	struct OpenAiGeminiStreamChunk {
		#[serde(default)]
		id: String,
		#[serde(default)]
		model: String,
		#[serde(default)]
		service_tier: Option<String>,
		#[serde(default)]
		choices: Vec<OpenAiGeminiStreamChoice>,
		#[serde(default)]
		usage: Option<completions::typed::Usage>,
	}

	#[derive(Debug, Default, Deserialize)]
	struct OpenAiGeminiStreamChoice {
		#[serde(default)]
		delta: OpenAiGeminiStreamDelta,
		#[serde(default)]
		finish_reason: Option<String>,
	}

	#[derive(Debug, Default, Deserialize)]
	struct OpenAiGeminiStreamDelta {
		#[serde(default)]
		content: Option<String>,
		#[serde(default)]
		reasoning_content: Option<String>,
		#[serde(default)]
		tool_calls: Option<Vec<OpenAiGeminiToolCallChunk>>,
	}

	#[derive(Debug, Default, Deserialize)]
	struct OpenAiGeminiToolCallChunk {
		#[serde(default)]
		index: u32,
		#[serde(default)]
		id: Option<String>,
		#[serde(default)]
		function: Option<OpenAiGeminiFunctionCallStream>,
	}

	#[derive(Debug, Default, Deserialize)]
	struct OpenAiGeminiFunctionCallStream {
		#[serde(default)]
		name: Option<String>,
		#[serde(default)]
		arguments: Option<String>,
	}

	pub fn translate_response(bytes: &Bytes, _model: &str) -> Result<Box<dyn ResponseType>, AIError> {
		let resp = serde_json::from_slice::<completions::typed::Response>(bytes)
			.map_err(AIError::ResponseParsing)?;
		let choice =
			resp.choices.into_iter().next().ok_or_else(|| {
				AIError::InvalidResponse(strng::literal!("chat response missing choices"))
			})?;

		let has_tool_calls = choice
			.message
			.tool_calls
			.as_ref()
			.map(|calls| !calls.is_empty())
			.unwrap_or(false);
		let status = response_status(choice.finish_reason.as_ref(), has_tool_calls).to_string();

		let mut output = Vec::new();
		let mut message_content = Vec::new();
		if let Some(text) = choice.message.content
			&& !text.is_empty()
		{
			message_content.push(responses::typed::OutputMessageContent::OutputText(
				responses::typed::OutputTextContent {
					annotations: Vec::new(),
					logprobs: None,
					text,
				},
			));
		}
		if let Some(refusal) = choice.message.refusal
			&& !refusal.is_empty()
		{
			message_content.push(responses::typed::OutputMessageContent::Refusal(
				RefusalContent { refusal },
			));
		}
		if !message_content.is_empty() {
			output.push(responses::typed::OutputItem::Message(
				responses::typed::OutputMessage {
					content: message_content,
					id: generate_item_id("msg"),
					role: responses::typed::AssistantRole::Assistant,
					phase: None,
					status: responses::typed::OutputStatus::Completed,
				},
			));
		}
		if let Some(tool_calls) = choice.message.tool_calls {
			for call in tool_calls {
				match call {
					completions::typed::MessageToolCalls::Function(call) => {
						output.push(responses::typed::OutputItem::FunctionCall(
							responses::typed::FunctionToolCall {
								arguments: call.function.arguments,
								call_id: call.id,
								namespace: None,
								name: call.function.name,
								id: Some(generate_item_id("call")),
								status: Some(responses::typed::OutputStatus::Completed),
							},
						));
					},
					completions::typed::MessageToolCalls::Custom(_) => {},
				}
			}
		}

		let response = responses::Response {
			id: resp.id,
			status,
			output,
			model: resp.model,
			service_tier: resp.service_tier.as_ref().and_then(|tier| {
				serde_json::to_value(tier)
					.ok()?
					.as_str()
					.map(ToOwned::to_owned)
			}),
			usage: usage_to_responses(resp.usage),
			rest: serde_json::Value::Object(serde_json::Map::new()),
		};
		Ok(Box::new(response))
	}

	pub fn translate_stream(b: Body, buffer_limit: usize, log: AmendOnDrop) -> Body {
		#[derive(Default)]
		struct PendingToolCall {
			item_id: String,
			call_id: String,
			name: String,
			arguments: String,
			output_index: u32,
			announced: bool,
		}

		#[derive(Default)]
		struct StreamState {
			started: bool,
			sequence_number: u64,
			message_item_done: bool,
			message_item_id: String,
			next_output_index: u32,
			tool_calls: BTreeMap<u32, PendingToolCall>,
			finish_reason: Option<String>,
			usage: Option<completions::typed::Usage>,
			saw_token: bool,
			response_builder: Option<responses::ResponseBuilder>,
			model: String,
			text_output: String,
		}

		let mut state = StreamState {
			message_item_id: generate_item_id("msg"),
			next_output_index: 1,
			..Default::default()
		};

		parse::sse::json_transform_multi::<Value, _, _>(b, buffer_limit, move |event| match event {
			SseJsonEvent::Data(Ok(raw_chunk)) => {
				let chunk = match parse_stream_chunk(raw_chunk) {
					Ok(chunk) => chunk,
					Err(err) => {
						tracing::warn!(%err, "failed to interpret Gemini streaming chat-completions chunk");
						state.sequence_number += 1;
						return vec![(
							"error",
							types::responses::typed::ResponseStreamEvent::ResponseError(
								types::responses::typed::ResponseErrorEvent {
									sequence_number: state.sequence_number,
									code: None,
									message: "Stream processing error".to_string(),
									param: None,
								},
							),
						)];
					},
				};
				let mut events: Vec<(&'static str, types::responses::typed::ResponseStreamEvent)> =
					Vec::new();

				if !chunk.model.is_empty() {
					state.model = chunk.model.clone();
					log.non_atomic_mutate(|r| {
						r.response.provider_model = Some(strng::new(&chunk.model));
					});
				}
				if let Some(service_tier) = &chunk.service_tier {
					log.non_atomic_mutate(|r| {
						r.response.service_tier = Some(strng::new(service_tier));
					});
				}

				if !state.started {
					state.started = true;
					state.model = chunk.model.clone();
					state.response_builder = Some(types::responses::ResponseBuilder::new(
						chunk.id.clone(),
						chunk.model.clone(),
					));

					state.sequence_number += 1;
					events.push((
						"event",
						state
							.response_builder
							.as_ref()
							.expect("builder initialized")
							.created_event(state.sequence_number),
					));

					state.sequence_number += 1;
					events.push((
						"event",
						types::responses::typed::ResponseStreamEvent::ResponseOutputItemAdded(
							types::responses::typed::ResponseOutputItemAddedEvent {
								sequence_number: state.sequence_number,
								output_index: 0,
								item: types::responses::typed::OutputItem::Message(
									types::responses::typed::OutputMessage {
										content: Vec::new(),
										id: state.message_item_id.clone(),
										role: types::responses::typed::AssistantRole::Assistant,
										phase: None,
										status: types::responses::typed::OutputStatus::InProgress,
									},
								),
							},
						),
					));
				}

				if let Some(usage) = chunk.usage.clone() {
					state.usage = Some(usage.clone());
					log.non_atomic_mutate(|r| {
						r.response.input_tokens = Some(usage.prompt_tokens as u64);
						r.response.output_tokens = Some(normalized_completion_tokens(&usage) as u64);
						r.response.total_tokens = Some(usage.total_tokens as u64);
						r.response.cached_input_tokens = usage
							.prompt_tokens_details
							.as_ref()
							.and_then(|d| d.cached_tokens);
						r.response.reasoning_tokens = usage
							.completion_tokens_details
							.as_ref()
							.and_then(|d| d.reasoning_tokens);
					});
				}

				if let Some(choice) = chunk.choices.first() {
					if let Some(finish_reason) = &choice.finish_reason {
						state.finish_reason = Some(finish_reason.to_ascii_lowercase());
					}

					let mut saw_any_text_delta = false;
					if let Some(delta) = &choice.delta.content
						&& !delta.is_empty()
					{
						saw_any_text_delta = true;
						state.text_output.push_str(delta);
						state.sequence_number += 1;
						events.push((
							"event",
							types::responses::typed::ResponseStreamEvent::ResponseOutputTextDelta(
								types::responses::typed::ResponseTextDeltaEvent {
									sequence_number: state.sequence_number,
									item_id: state.message_item_id.clone(),
									output_index: 0,
									content_index: 0,
									delta: delta.clone(),
									logprobs: None,
								},
							),
						));
					}
					if let Some(reasoning_delta) = &choice.delta.reasoning_content
						&& !reasoning_delta.is_empty()
					{
						saw_any_text_delta = true;
						state.text_output.push_str(reasoning_delta);
					}
					if saw_any_text_delta {
						let estimated_output_tokens =
							estimate_text_token_count(&state.model, &state.text_output);
						if !state.saw_token {
							state.saw_token = true;
							log.non_atomic_mutate(|r| {
								r.response.first_token = Some(Instant::now());
							});
						}
						log.non_atomic_mutate(|r| {
							r.response.output_tokens = Some(estimated_output_tokens);
							if r.response.total_tokens.is_none()
								&& let Some(input_tokens) = r.response.input_tokens
							{
								r.response.total_tokens = Some(input_tokens + estimated_output_tokens);
							}
						});
					}

					if let Some(tool_calls) = &choice.delta.tool_calls {
						for tool_call in tool_calls {
							let entry = if let Some(entry) = state.tool_calls.get_mut(&tool_call.index) {
								entry
							} else {
								let output_index = state.next_output_index;
								state.next_output_index += 1;
								state
									.tool_calls
									.entry(tool_call.index)
									.or_insert(PendingToolCall {
										item_id: generate_item_id("call"),
										call_id: tool_call.id.clone().unwrap_or_default(),
										name: tool_call
											.function
											.as_ref()
											.and_then(|f| f.name.clone())
											.unwrap_or_default(),
										arguments: String::new(),
										output_index,
										announced: false,
									})
							};

							if entry.call_id.is_empty() {
								entry.call_id = tool_call.id.clone().unwrap_or_default();
							}
							if entry.name.is_empty() {
								entry.name = tool_call
									.function
									.as_ref()
									.and_then(|f| f.name.clone())
									.unwrap_or_default();
							}

							if !entry.announced {
								entry.announced = true;
								state.sequence_number += 1;
								events.push((
									"event",
									types::responses::typed::ResponseStreamEvent::ResponseOutputItemAdded(
										types::responses::typed::ResponseOutputItemAddedEvent {
											sequence_number: state.sequence_number,
											output_index: entry.output_index,
											item: types::responses::typed::OutputItem::FunctionCall(
												types::responses::typed::FunctionToolCall {
													arguments: String::new(),
													call_id: entry.call_id.clone(),
													namespace: None,
													name: entry.name.clone(),
													id: Some(entry.item_id.clone()),
													status: Some(types::responses::typed::OutputStatus::InProgress),
												},
											),
										},
									),
								));
							}

							if let Some(arguments_delta) = tool_call
								.function
								.as_ref()
								.and_then(|f| f.arguments.clone())
								&& !arguments_delta.is_empty()
							{
								entry.arguments.push_str(&arguments_delta);
								state.sequence_number += 1;
								events.push((
									"event",
									types::responses::typed::ResponseStreamEvent::ResponseFunctionCallArgumentsDelta(
										types::responses::typed::ResponseFunctionCallArgumentsDeltaEvent {
											sequence_number: state.sequence_number,
											item_id: entry.item_id.clone(),
											output_index: entry.output_index,
											delta: arguments_delta,
										},
									),
								));
							}
						}
					}
				}

				events
			},
			SseJsonEvent::Data(Err(err)) => {
				tracing::warn!(%err, "failed to parse Gemini streaming chat-completions chunk");
				state.sequence_number += 1;
				vec![(
					"error",
					types::responses::typed::ResponseStreamEvent::ResponseError(
						types::responses::typed::ResponseErrorEvent {
							sequence_number: state.sequence_number,
							code: None,
							message: "Stream processing error".to_string(),
							param: None,
						},
					),
				)]
			},
			SseJsonEvent::Done => {
				if !state.started {
					state.started = true;
					state.response_builder = Some(types::responses::ResponseBuilder::new("", ""));
					let mut events: Vec<(&'static str, types::responses::typed::ResponseStreamEvent)> =
						Vec::new();
					state.sequence_number += 1;
					events.push((
						"event",
						state
							.response_builder
							.as_ref()
							.expect("builder initialized")
							.created_event(state.sequence_number),
					));
					state.sequence_number += 1;
					events.push((
						"event",
						types::responses::typed::ResponseStreamEvent::ResponseOutputItemAdded(
							types::responses::typed::ResponseOutputItemAddedEvent {
								sequence_number: state.sequence_number,
								output_index: 0,
								item: types::responses::typed::OutputItem::Message(
									types::responses::typed::OutputMessage {
										content: Vec::new(),
										id: state.message_item_id.clone(),
										role: types::responses::typed::AssistantRole::Assistant,
										phase: None,
										status: types::responses::typed::OutputStatus::InProgress,
									},
								),
							},
						),
					));
					state.message_item_done = true;
					state.sequence_number += 1;
					events.push((
						"event",
						types::responses::typed::ResponseStreamEvent::ResponseOutputItemDone(
							types::responses::typed::ResponseOutputItemDoneEvent {
								sequence_number: state.sequence_number,
								output_index: 0,
								item: types::responses::typed::OutputItem::Message(
									types::responses::typed::OutputMessage {
										content: Vec::new(),
										id: state.message_item_id.clone(),
										role: types::responses::typed::AssistantRole::Assistant,
										phase: None,
										status: types::responses::typed::OutputStatus::Completed,
									},
								),
							},
						),
					));
					state.sequence_number += 1;
					events.push((
						"event",
						state
							.response_builder
							.as_ref()
							.expect("builder initialized")
							.completed_event(state.sequence_number, None),
					));
					return events;
				}
				let mut events: Vec<(&'static str, types::responses::typed::ResponseStreamEvent)> =
					Vec::new();

				if !state.message_item_done {
					state.message_item_done = true;
					state.sequence_number += 1;
					events.push((
						"event",
						types::responses::typed::ResponseStreamEvent::ResponseOutputItemDone(
							types::responses::typed::ResponseOutputItemDoneEvent {
								sequence_number: state.sequence_number,
								output_index: 0,
								item: types::responses::typed::OutputItem::Message(
									types::responses::typed::OutputMessage {
										content: Vec::new(),
										id: state.message_item_id.clone(),
										role: types::responses::typed::AssistantRole::Assistant,
										phase: None,
										status: types::responses::typed::OutputStatus::Completed,
									},
								),
							},
						),
					));
				}

				for tool_call in state.tool_calls.values() {
					state.sequence_number += 1;
					events.push((
						"event",
						types::responses::typed::ResponseStreamEvent::ResponseFunctionCallArgumentsDone(
							types::responses::typed::ResponseFunctionCallArgumentsDoneEvent {
								name: Some(tool_call.name.clone()),
								sequence_number: state.sequence_number,
								item_id: tool_call.item_id.clone(),
								output_index: tool_call.output_index,
								arguments: tool_call.arguments.clone(),
							},
						),
					));

					state.sequence_number += 1;
					events.push((
						"event",
						types::responses::typed::ResponseStreamEvent::ResponseOutputItemDone(
							types::responses::typed::ResponseOutputItemDoneEvent {
								sequence_number: state.sequence_number,
								output_index: tool_call.output_index,
								item: types::responses::typed::OutputItem::FunctionCall(
									types::responses::typed::FunctionToolCall {
										arguments: tool_call.arguments.clone(),
										call_id: tool_call.call_id.clone(),
										namespace: None,
										name: tool_call.name.clone(),
										id: Some(tool_call.item_id.clone()),
										status: Some(types::responses::typed::OutputStatus::Completed),
									},
								),
							},
						),
					));
				}

				if state.usage.is_none() && !state.text_output.is_empty() {
					let output_tokens = estimate_text_token_count(&state.model, &state.text_output);
					log.non_atomic_mutate(|r| {
						r.response.provider_model = Some(strng::new(&state.model));
						r.response.output_tokens = Some(output_tokens);
						if r.response.total_tokens.is_none()
							&& let Some(input_tokens) = r.response.input_tokens
						{
							r.response.total_tokens = Some(input_tokens + output_tokens);
						}
					});
				}
				let usage = usage_to_stream_usage(state.usage.take());
				state.sequence_number += 1;
				let builder = state
					.response_builder
					.as_ref()
					.expect("builder initialized");
				let final_event = match state.finish_reason.as_deref() {
					Some("length") => builder.incomplete_event(
						state.sequence_number,
						usage,
						types::responses::typed::IncompleteDetails {
							reason: "max_tokens".to_string(),
						},
					),
					Some("content_filter") => builder.failed_event(
						state.sequence_number,
						usage,
						types::responses::typed::ErrorObject {
							code: "content_filter".to_string(),
							message: "Content filtered".to_string(),
						},
					),
					_ => builder.completed_event(state.sequence_number, usage),
				};
				events.push(("event", final_event));
				events
			},
		})
	}

	fn parse_stream_chunk(value: Value) -> Result<GeminiStreamChunk, String> {
		if value.get("choices").is_some() || value.get("usage").is_some() {
			let chunk: OpenAiGeminiStreamChunk =
				serde_json::from_value(value).map_err(|err| err.to_string())?;
			return Ok(GeminiStreamChunk {
				id: chunk.id,
				model: chunk.model,
				service_tier: chunk.service_tier,
				choices: chunk
					.choices
					.into_iter()
					.map(|choice| GeminiStreamChoice {
						delta: GeminiStreamDelta {
							content: choice.delta.content,
							reasoning_content: choice.delta.reasoning_content,
							tool_calls: choice.delta.tool_calls.map(|tool_calls| {
								tool_calls
									.into_iter()
									.map(|tool_call| GeminiToolCallChunk {
										index: tool_call.index,
										id: tool_call.id,
										function: tool_call.function.map(|function| GeminiFunctionCallStream {
											name: function.name,
											arguments: function.arguments,
										}),
									})
									.collect()
							}),
						},
						finish_reason: choice
							.finish_reason
							.map(|reason| normalize_finish_reason(&reason)),
					})
					.collect(),
				usage: chunk.usage,
			});
		}

		if value.get("candidates").is_some()
			|| value.get("usageMetadata").is_some()
			|| value.get("responseId").is_some()
		{
			return Ok(parse_native_stream_chunk(&value));
		}

		Err(format!(
			"unrecognized Gemini stream chunk shape: {}",
			truncate_json_for_log(&value)
		))
	}

	fn parse_native_stream_chunk(value: &Value) -> GeminiStreamChunk {
		let candidate = value
			.get("candidates")
			.and_then(Value::as_array)
			.and_then(|candidates| candidates.first());
		let (content, tool_calls) = candidate
			.map(extract_native_candidate_delta)
			.unwrap_or_default();

		GeminiStreamChunk {
			id: value
				.get("responseId")
				.and_then(Value::as_str)
				.unwrap_or_default()
				.to_string(),
			model: value
				.get("modelVersion")
				.or_else(|| value.get("model"))
				.and_then(Value::as_str)
				.unwrap_or_default()
				.to_string(),
			service_tier: None,
			choices: candidate
				.map(|candidate| GeminiStreamChoice {
					delta: GeminiStreamDelta {
						content,
						reasoning_content: None,
						tool_calls,
					},
					finish_reason: candidate
						.get("finishReason")
						.and_then(Value::as_str)
						.map(normalize_finish_reason),
				})
				.into_iter()
				.collect(),
			usage: parse_native_usage(value.get("usageMetadata")),
		}
	}

	fn extract_native_candidate_delta(
		candidate: &Value,
	) -> (Option<String>, Option<Vec<GeminiToolCallChunk>>) {
		let mut texts = Vec::new();
		let mut tool_calls = Vec::new();

		for (index, part) in candidate
			.get("content")
			.and_then(|content| content.get("parts"))
			.and_then(Value::as_array)
			.into_iter()
			.flatten()
			.enumerate()
		{
			if let Some(text) = part.get("text").and_then(Value::as_str)
				&& !text.is_empty()
			{
				texts.push(text.to_string());
			}
			if let Some(function_call) = part.get("functionCall") {
				let name = function_call
					.get("name")
					.and_then(Value::as_str)
					.map(ToOwned::to_owned);
				let arguments = function_call
					.get("args")
					.and_then(|args| serde_json::to_string(args).ok());
				if name.is_some() || arguments.is_some() {
					tool_calls.push(GeminiToolCallChunk {
						index: index as u32,
						id: None,
						function: Some(GeminiFunctionCallStream { name, arguments }),
					});
				}
			}
		}

		(
			if texts.is_empty() {
				None
			} else {
				Some(texts.join("\n"))
			},
			if tool_calls.is_empty() {
				None
			} else {
				Some(tool_calls)
			},
		)
	}

	fn parse_native_usage(usage: Option<&Value>) -> Option<completions::typed::Usage> {
		let usage = usage?.as_object()?;
		let prompt_tokens = as_u32(usage.get("promptTokenCount")).unwrap_or_default();
		let total_tokens = as_u32(usage.get("totalTokenCount")).unwrap_or_default();
		let completion_tokens = as_u32(usage.get("candidatesTokenCount"))
			.or_else(|| total_tokens.checked_sub(prompt_tokens))
			.unwrap_or_default();
		let cached_tokens = usage.get("cachedContentTokenCount").and_then(Value::as_u64);
		let reasoning_tokens = usage
			.get("thoughtsTokenCount")
			.or_else(|| usage.get("reasoningTokenCount"))
			.and_then(Value::as_u64);

		Some(completions::typed::Usage {
			prompt_tokens,
			completion_tokens,
			total_tokens,
			completion_tokens_details: reasoning_tokens.map(|reasoning_tokens| {
				completions::typed::UsageCompletionDetails {
					reasoning_tokens: Some(reasoning_tokens),
					audio_tokens: None,
					rest: Value::Object(serde_json::Map::new()),
				}
			}),
			prompt_tokens_details: cached_tokens.map(|cached_tokens| {
				completions::typed::UsagePromptDetails {
					cached_tokens: Some(cached_tokens),
					audio_tokens: None,
					rest: Value::Object(serde_json::Map::new()),
				}
			}),
			cache_read_input_tokens: None,
			cache_creation_input_tokens: None,
		})
	}

	fn as_u32(value: Option<&Value>) -> Option<u32> {
		value
			.and_then(Value::as_u64)
			.and_then(|value| value.try_into().ok())
	}

	fn normalize_finish_reason(reason: &str) -> String {
		match reason.to_ascii_uppercase().as_str() {
			"STOP" => "stop".to_string(),
			"MAX_TOKENS" => "length".to_string(),
			"CONTENT_FILTER" | "SAFETY" | "PROHIBITED_CONTENT" | "BLOCKLIST" | "SPII" | "RECITATION" => {
				"content_filter".to_string()
			},
			other => other.to_ascii_lowercase(),
		}
	}

	fn truncate_json_for_log(value: &Value) -> String {
		let rendered = value.to_string();
		if rendered.len() > 500 {
			format!("{}...", &rendered[..500])
		} else {
			rendered
		}
	}

	fn estimate_text_token_count(model: &str, text: &str) -> u64 {
		let tokenizer = get_tokenizer(model).unwrap_or(Tokenizer::Cl100kBase);
		crate::llm::get_bpe_from_tokenizer(tokenizer)
			.encode_ordinary(text)
			.len() as u64
	}

	fn normalized_completion_tokens(usage: &completions::typed::Usage) -> u32 {
		let derived = usage.total_tokens.saturating_sub(usage.prompt_tokens);
		if usage.completion_tokens == 0 && derived > 0 {
			derived
		} else {
			usage.completion_tokens
		}
	}

	fn usage_to_stream_usage(
		usage: Option<completions::typed::Usage>,
	) -> Option<types::responses::typed::ResponseUsage> {
		usage.map(|usage| types::responses::typed::ResponseUsage {
			input_tokens: usage.prompt_tokens,
			output_tokens: normalized_completion_tokens(&usage),
			total_tokens: usage.total_tokens,
			input_tokens_details: types::responses::typed::InputTokenDetails {
				cached_tokens: usage
					.prompt_tokens_details
					.as_ref()
					.and_then(|d| d.cached_tokens)
					.unwrap_or_default() as u32,
			},
			output_tokens_details: types::responses::typed::OutputTokenDetails {
				reasoning_tokens: usage
					.completion_tokens_details
					.as_ref()
					.and_then(|d| d.reasoning_tokens)
					.unwrap_or_default() as u32,
			},
		})
	}

	fn usage_to_responses(
		usage: Option<completions::typed::Usage>,
	) -> Option<types::responses::Usage> {
		usage.map(|usage| types::responses::Usage {
			input_tokens: usage.prompt_tokens as u64,
			output_tokens: normalized_completion_tokens(&usage) as u64,
			input_tokens_details: Some(types::responses::UsageInputDetails {
				cached_tokens: usage
					.prompt_tokens_details
					.as_ref()
					.and_then(|d| d.cached_tokens),
				rest: serde_json::Value::Object(serde_json::Map::new()),
			}),
			output_tokens_details: Some(types::responses::UsageOutputDetails {
				reasoning_tokens: usage
					.completion_tokens_details
					.as_ref()
					.and_then(|d| d.reasoning_tokens),
				rest: serde_json::Value::Object(serde_json::Map::new()),
			}),
			rest: serde_json::Value::Object(serde_json::Map::new()),
		})
	}

	fn response_status(
		finish_reason: Option<&completions::typed::FinishReason>,
		has_tool_calls: bool,
	) -> &'static str {
		if has_tool_calls {
			return "requires_action";
		}
		match finish_reason {
			Some(completions::typed::FinishReason::Length) => "incomplete",
			Some(completions::typed::FinishReason::ContentFilter) => "failed",
			_ => "completed",
		}
	}

	fn generate_item_id(prefix: &str) -> String {
		format!("{prefix}_{:016x}", rand::rng().random::<u64>())
	}
}

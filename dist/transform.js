import { buildBillingHeaderValue } from "./cch.js";
import { CLAUDE_CODE_ENTRYPOINT, CLAUDE_CODE_IDENTITY, OPENCODE_IDENTITY_PREFIX, PARAGRAPH_REMOVAL_ANCHORS, REQUIRED_BETAS, TEXT_REPLACEMENTS, TOOL_PREFIX, USER_AGENT, } from "./constants.js";
/**
 * Prefix a tool name with TOOL_PREFIX and uppercase the first character.
 * Claude Code uses PascalCase tool names (e.g. mcp_Bash, mcp_Read);
 * lowercase names (mcp_bash, mcp_read) are flagged as non-Claude-Code clients.
 */
function prefixName(name) {
    return `${TOOL_PREFIX}${name.charAt(0).toUpperCase()}${name.slice(1)}`;
}
/**
 * Reverse prefixName: strip TOOL_PREFIX and restore the original leading case.
 */
function unprefixName(name) {
    // StructuredOutput is still used as StructuredOutput
    if (name === 'StructuredOutput') {
        return name;
    }
    return `${name.charAt(0).toLowerCase()}${name.slice(1)}`;
}
/**
 * Merge headers from a Request object and/or a RequestInit headers value
 * into a single Headers instance.
 */
export function mergeHeaders(input, init) {
    const headers = new Headers();
    if (input instanceof Request) {
        input.headers.forEach((value, key) => {
            headers.set(key, value);
        });
    }
    const initHeaders = init?.headers;
    if (initHeaders) {
        if (initHeaders instanceof Headers) {
            initHeaders.forEach((value, key) => {
                headers.set(key, value);
            });
        }
        else if (Array.isArray(initHeaders)) {
            for (const entry of initHeaders) {
                const [key, value] = entry;
                if (typeof value !== 'undefined') {
                    headers.set(key, String(value));
                }
            }
        }
        else {
            for (const [key, value] of Object.entries(initHeaders)) {
                if (typeof value !== 'undefined') {
                    headers.set(key, String(value));
                }
            }
        }
    }
    return headers;
}
/**
 * Merge incoming beta headers with the required OAuth betas, deduplicating.
 */
export function mergeBetaHeaders(headers) {
    const incomingBeta = headers.get('anthropic-beta') || '';
    const incomingBetasList = incomingBeta
        .split(',')
        .map((b) => b.trim())
        .filter(Boolean);
    return [...new Set([...REQUIRED_BETAS, ...incomingBetasList])].join(',');
}
/**
 * Set OAuth-required headers on the request: authorization, beta, user-agent.
 * Removes x-api-key since we're using OAuth.
 */
export function setOAuthHeaders(headers, accessToken) {
    headers.set('authorization', `Bearer ${accessToken}`);
    headers.set('anthropic-beta', mergeBetaHeaders(headers));
    headers.set('user-agent', USER_AGENT);
    headers.delete('x-api-key');
    return headers;
}
/**
 * Add TOOL_PREFIX to tool names in the request body.
 * Prefixes both tool definitions and tool_use blocks in messages.
 */
export function prefixToolNames(parsed) {
    if (parsed.tools && Array.isArray(parsed.tools)) {
        parsed.tools = parsed.tools.map((tool) => ({
            ...tool,
            name: tool.name ? prefixName(tool.name) : tool.name,
        }));
    }
    if (parsed.messages && Array.isArray(parsed.messages)) {
        parsed.messages = parsed.messages.map((msg) => {
            if (msg.content && Array.isArray(msg.content)) {
                msg.content = msg.content.map((block) => {
                    if (block.type === 'tool_use' && block.name) {
                        return { ...block, name: prefixName(block.name) };
                    }
                    return block;
                });
            }
            return msg;
        });
    }
    return JSON.stringify(parsed);
}
/**
 * Strip TOOL_PREFIX from tool names in streaming response text.
 */
export function stripToolPrefix(text) {
    return text.replace(/"name"\s*:\s*"mcp_([^"]+)"/g, (_match, name) => `"name": "${unprefixName(name)}"`);
}
/**
 * Check if TLS verification should be skipped for custom API endpoints.
 * Only effective when ANTHROPIC_BASE_URL is also set.
 */
export function isInsecure() {
    if (!process.env.ANTHROPIC_BASE_URL?.trim())
        return false;
    const raw = process.env.ANTHROPIC_INSECURE?.trim();
    return raw === '1' || raw === 'true';
}
/**
 * Parse ANTHROPIC_BASE_URL from the environment.
 * Returns a valid HTTP(S) URL or null if unset/invalid.
 */
function resolveBaseUrl() {
    const raw = process.env.ANTHROPIC_BASE_URL?.trim();
    if (!raw)
        return null;
    try {
        const baseUrl = new URL(raw);
        if ((baseUrl.protocol !== 'http:' && baseUrl.protocol !== 'https:') ||
            baseUrl.username ||
            baseUrl.password) {
            return null;
        }
        return baseUrl;
    }
    catch {
        return null;
    }
}
/**
 * Rewrite the request URL to add ?beta=true for /v1/messages requests.
 * When ANTHROPIC_BASE_URL is set, overrides the origin (protocol + host)
 * for all API requests flowing through the fetch wrapper.
 * Returns the modified input and URL (if applicable).
 */
export function rewriteUrl(input) {
    let requestUrl = null;
    try {
        if (typeof input === 'string' || input instanceof URL) {
            requestUrl = new URL(input.toString());
        }
        else if (input instanceof Request) {
            requestUrl = new URL(input.url);
        }
    }
    catch {
        requestUrl = null;
    }
    if (!requestUrl)
        return { input, url: null };
    const originalHref = requestUrl.href;
    const baseUrl = resolveBaseUrl();
    if (baseUrl) {
        requestUrl.protocol = baseUrl.protocol;
        requestUrl.host = baseUrl.host;
    }
    if (requestUrl.pathname === '/v1/messages' &&
        !requestUrl.searchParams.has('beta')) {
        requestUrl.searchParams.set('beta', 'true');
    }
    if (requestUrl.href === originalHref) {
        return { input, url: requestUrl };
    }
    const newInput = input instanceof Request
        ? new Request(requestUrl.toString(), input)
        : requestUrl;
    return { input: newInput, url: requestUrl };
}
/**
 * Sanitize OpenCode-branded strings from the system prompt text.
 *
 * 1. Removes the OPENCODE_IDENTITY paragraph.
 * 2. Removes any paragraph (text between blank lines) that contains
 *    one of the PARAGRAPH_REMOVAL_ANCHORS — typically URLs that
 *    identify OpenCode-specific content.
 * 3. Applies TEXT_REPLACEMENTS for inline occurrences of "OpenCode"
 *    inside paragraphs we want to keep.
 *
 * This approach is resilient to upstream rewording of the OpenCode
 * prompt — as long as the anchor strings (URLs, etc.) still appear
 * somewhere in the paragraph, the removal works.
 */
export function sanitizeSystemText(text) {
    // Split into paragraphs (separated by one or more blank lines)
    const paragraphs = text.split(/\n\n+/);
    const filtered = paragraphs.filter((paragraph) => {
        if (paragraph.includes(OPENCODE_IDENTITY_PREFIX)) {
            // If the paragraph contains the identity, drop it entirely
            return false;
        }
        // Remove paragraphs containing any removal anchor
        for (const anchor of PARAGRAPH_REMOVAL_ANCHORS) {
            if (paragraph.includes(anchor))
                return false;
        }
        return true;
    });
    let result = filtered.join('\n\n');
    // Apply inline text replacements
    for (const rule of TEXT_REPLACEMENTS) {
        result = result.replace(rule.match, rule.replacement);
    }
    return result.trim();
}
function isRecord(value) {
    return value != null && typeof value === 'object' && !Array.isArray(value);
}
/**
 * Sanitize system prompt and prepend Claude Code identity.
 * Handles all Anthropic API system formats: undefined, string, or array of text blocks.
 */
export function prependClaudeCodeIdentity(system) {
    const identityBlock = {
        type: 'text',
        text: CLAUDE_CODE_IDENTITY,
    };
    if (system == null)
        return [identityBlock];
    if (typeof system === 'string') {
        const sanitized = sanitizeSystemText(system);
        if (sanitized === CLAUDE_CODE_IDENTITY)
            return [identityBlock];
        return [identityBlock, { type: 'text', text: sanitized }];
    }
    if (isRecord(system)) {
        const type = typeof system.type === 'string' ? system.type : 'text';
        const text = typeof system.text === 'string' ? system.text : '';
        return [identityBlock, { ...system, type, text: sanitizeSystemText(text) }];
    }
    if (!Array.isArray(system))
        return [identityBlock];
    const sanitized = system.map((item) => {
        if (typeof item === 'string') {
            return { type: 'text', text: sanitizeSystemText(item) };
        }
        if (isRecord(item) &&
            item.type === 'text' &&
            typeof item.text === 'string') {
            return {
                ...item,
                type: 'text',
                text: sanitizeSystemText(item.text),
            };
        }
        return { type: 'text', text: String(item) };
    });
    // Idempotency: don't double-prepend if first block already has the identity
    if (sanitized[0]?.text === CLAUDE_CODE_IDENTITY) {
        return sanitized;
    }
    return [identityBlock, ...sanitized];
}
/**
 * Rewrite the full request body: sanitize system prompt and prefix tool names.
 */
export function rewriteRequestBody(body) {
    try {
        const parsed = JSON.parse(body);
        const billingHeader = Array.isArray(parsed.messages) &&
            parsed.messages.some((message) => message.role === 'user')
            ? buildBillingHeaderValue(parsed.messages, undefined, CLAUDE_CODE_ENTRYPOINT)
            : null;
        // Sanitize system prompt and prepend Claude Code identity
        parsed.system = prependClaudeCodeIdentity(parsed.system);
        // Prepend the billing header as a separate system block so the
        // final layout is: [billing header, identity, ...rest]
        if (billingHeader && Array.isArray(parsed.system)) {
            parsed.system.unshift({ type: 'text', text: billingHeader });
        }
        return prefixToolNames(parsed);
    }
    catch {
        return body;
    }
}
/**
 * Create a streaming response that strips the tool prefix from tool names.
 */
export function createStrippedStream(response) {
    if (!response.body)
        return response;
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
    let pending = '';
    const stream = new ReadableStream({
        async pull(controller) {
            while (true) {
                const { done, value } = await reader.read();
                if (done) {
                    pending += decoder.decode();
                    if (pending)
                        controller.enqueue(encoder.encode(stripToolPrefix(pending)));
                    controller.close();
                    return;
                }
                pending += decoder.decode(value, { stream: true });
                const boundary = pending.lastIndexOf('\n');
                if (boundary === -1)
                    continue;
                controller.enqueue(encoder.encode(stripToolPrefix(pending.slice(0, boundary + 1))));
                pending = pending.slice(boundary + 1);
                return;
            }
        },
        cancel(reason) {
            return reader.cancel(reason);
        },
    });
    return new Response(stream, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
    });
}

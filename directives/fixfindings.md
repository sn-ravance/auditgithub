# Fix Findings Directive

## Purpose
When the "Ask AI" button triggers an "AI Security Analysis" and returns a successful response (non-error), append the AI-generated analysis to the finding's description and persist it to the database.

## Current Implementation

The AI Security Analysis is triggered via:
- **Frontend**: `AskAIDialog` component calls `/ai/analyze-finding` endpoint
- **Backend**: `src/api/routers/ai.py` → `analyze_finding_endpoint()`
- **AI Provider**: `src/ai_agent/providers/claude.py` → `analyze_finding()`

## System Prompts for AI Security Analysis

### For Claude 4.5 (Anthropic)

```
You are a senior security engineer. Analyze the provided security finding.

Finding Details:
{finding_context as JSON}

Provide a detailed analysis including:
1. **Vulnerability Assessment**: What is the security risk and potential impact?
2. **Attack Vector**: How could an attacker exploit this vulnerability?
3. **Remediation Steps**: Specific, actionable steps to fix the issue
4. **Code Fix**: If applicable, provide corrected code snippets
5. **Prevention**: How to prevent similar issues in the future

Your analysis will be appended to the finding's description in the database for future reference.
```

### For Gemini (Google)

```
You are a senior security engineer. Analyze the provided security finding.

Finding Details:
{finding_context as JSON}

Provide a detailed analysis including:
1. **Vulnerability Assessment**: What is the security risk and potential impact?
2. **Attack Vector**: How could an attacker exploit this vulnerability?
3. **Remediation Steps**: Specific, actionable steps to fix the issue
4. **Code Fix**: If applicable, provide corrected code snippets
5. **Prevention**: How to prevent similar issues in the future

Your analysis will be appended to the finding's description in the database for future reference.
```

## Backend Implementation

### API Endpoint: `/ai/analyze-finding` (POST)

Current flow in `src/api/routers/ai.py`:

1. Fetch finding from database by `finding_id` (UUID)
2. Convert finding to dict with: title, description, severity, file_path, line_start, line_end, code_snippet, finding_type, scanner
3. Call `ai_agent.analyze_finding(finding=finding_dict, user_prompt=request.prompt)`
4. Return `{"analysis": analysis}`

### Required Enhancement: Append Analysis to Finding Description

After receiving a successful AI analysis response, append it to the finding's description:

```python
# In analyze_finding_endpoint() after getting analysis
if analysis and not is_error_response(analysis):
    # Format the AI response with metadata
    from datetime import datetime
    timestamp = datetime.utcnow().isoformat()
    ai_header = "### 🤖 AI Security Analysis"
    
    # Check if analysis is already appended to avoid duplication
    if ai_header not in (finding.description or ""):
        formatted_analysis = f"""

{ai_header}
**Analyzed:** {timestamp}
**Provider:** {ai_agent.provider_name}

{analysis}

---
"""
        finding.description = f"{finding.description or ''}{formatted_analysis}"
        db.commit()
        logger.info(f"Appended AI Security Analysis to finding {request.finding_id}")
```

### Error Detection

A response is considered an error if it:
- Starts with "Error:" or "Failed:"
- Contains "AI analysis failed:"
- Contains "API key" errors
- Contains "rate limit" errors
- Contains "connection" errors
- Is empty or None

## File Locations

- **API Endpoint**: `src/api/routers/ai.py` → `analyze_finding_endpoint()`
- **Frontend Component**: `src/web-ui/components/AskAIDialog.tsx`
- **AI Provider (Claude)**: `src/ai_agent/providers/claude.py` → `analyze_finding()`
- **AI Provider (OpenAI)**: `src/ai_agent/providers/openai.py` → `analyze_finding()`
- **Agent Wrapper**: `src/ai_agent/reasoning.py` → `analyze_finding()`

## Testing

1. Go to the Findings page at http://localhost:3000/findings
2. Click "Ask AI" button on any finding
3. Wait for the AI Security Analysis to complete
4. Verify the analysis appears in the dialog
5. Check the finding's description in the database:
   ```sql
   SELECT description FROM findings WHERE finding_uuid = '<uuid>';
   ```
6. Confirm the AI analysis is appended with the 🤖 header
7. Refresh the finding detail page to confirm the update is visible

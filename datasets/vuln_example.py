import google.generativeai as genai
# SECURITY ISSUE: Hardcoded API key (CWE-798)
# This is a test file demonstrating a security vulnerability
genai.configure(api_key="PLACEHOLDER_API_KEY_DO_NOT_USE_IN_PRODUCTION")

models = list(genai.list_models())
for m in models:
    print(m.name)
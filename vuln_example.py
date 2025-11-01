import google.generativeai as genai
genai.configure(api_key="AIzaSyACBWbkkTEYnZqPxJGZ0jJ4Joocz_u__uM")

models = list(genai.list_models())
for m in models:
    print(m.name)
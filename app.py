import streamlit as st
import os
import json
# Import the specific Pydantic types for structured output
from google import genai
from google.genai.types import Schema

# --- 0. DEFINE STRUCTURED OUTPUT SCHEMA ---
# Define the expected JSON structure using a Python dictionary, 
# which is converted to a Schema object for the Gemini API.
RISK_SCHEMA = Schema(
    type="OBJECT",
    properties={
        "finding_summary": Schema(type="STRING", description="A one-sentence summary of the security finding."),
        "mitre_tactic": Schema(type="STRING", description="The most probable MITRE ATT&CK Tactic name."),
        "mitre_technique": Schema(type="STRING", description="The most probable MITRE ATT&CK Technique ID and name (e.g., T1078.001 - Valid Accounts)."),
        "nist_function": Schema(type="STRING", description="The most relevant NIST CSF Function (Identify, Protect, Detect, Respond, Recover)."),
        "nist_category": Schema(type="STRING", description="The most relevant NIST CSF Category."),
        "remediation_suggestion": Schema(type="STRING", description="A high-level, actionable remediation strategy.")
    },
    required=["finding_summary", "mitre_tactic", "mitre_technique", "nist_function", "nist_category", "remediation_suggestion"]
)

# --- 1. CONFIGURATION ---
# The genai client automatically looks for the GEMINI_API_KEY environment variable.
try:
    client = genai.Client()
except Exception as e:
    st.error("Error: Gemini API Client failed to initialize. Ensure GEMINI_API_KEY is set in your environment or Streamlit secrets.")
    st.stop()


# --- 2. CORE AI FUNCTION ---
def get_risk_mapping(finding_text):
    """Calls the Gemini API with a structured prompt to map findings."""

    # 1. DEFINE THE MASTER PROMPT STRING (using the PTCF framework)
    MASTER_PROMPT = f"""
You are a highly experienced Security Engineer and Risk Consultant.
Your TASK is to analyze the raw security finding provided below and map it to common security frameworks and controls.
Your entire response must STRICTLY adhere to the JSON schema provided in the configuration.

Raw Security Finding to Analyze:
{finding_text}
""" # The prompt string ends cleanly here.

    # 2. EXECUTE THE API CALL AND PARSING (The robust way)
    try:
        # Call the API, specifying JSON as the desired output format and passing the Schema
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=MASTER_PROMPT,
            config={
                'response_mime_type': 'application/json',
                'response_schema': RISK_SCHEMA
            }
        )
        
        # --- ROBUST CLEANING AND PARSING ---
        # Get raw text and remove leading/trailing whitespace
        raw_text = response.text.strip()
        
        # The Gemini API is designed for structured output, but we include robust cleaning just in case:
        if raw_text.startswith("```json"):
            raw_text = raw_text.strip("```json").strip("```")
        elif raw_text.startswith("```"):
            raw_text = raw_text.strip("```")

        # Attempt to parse the cleaned JSON output
        return json.loads(raw_text)
    
    except Exception as e:
        # Provide the raw text in the error message for better debugging
        return {"error": f"AI Parsing Error: Could not get structured output. Details: {e}. Raw Response (start): {raw_text[:50]}..."}


# --- 3. STREAMLIT UI ---
st.set_page_config(page_title="AI Risk Contextualization Engine", layout="wide")
st.title("🤖 AI Risk Mapping Bot")
st.markdown("Enter a raw security finding to automatically map it to MITRE ATT&CK and NIST CSF.") 

# Input Area
user_input = st.text_area(
    "Paste Raw Security Finding Here:",
    placeholder="e.g., Account 'svc_backup' has a password that expires in 365 days, violating the 90-day policy.",
    height=150
)

if st.button("Analyze Finding") and user_input:
    # Check if the user is running the app with the necessary variable set
    if "GEMINI_API_KEY" not in os.environ:
         st.error("API Key not found. Please set the 'GEMINI_API_KEY' environment variable and refresh.")
    else:
        with st.spinner('Thinking... Analyzing frameworks and controls...'):
            mapping_data = get_risk_mapping(user_input)

        if "error" in mapping_data:
            st.error(mapping_data["error"])
        else:
            st.subheader("✅ Analysis Results")
            st.caption(f'**Finding Summary:** {mapping_data.get("finding_summary", "N/A")}')
            st.markdown("---")
            
            # Display the output using columns for a clean look
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("MITRE ATT&CK Tactic", mapping_data.get("mitre_tactic", "N/A"))
                st.info(f'**Technique:** {mapping_data.get("mitre_technique", "N/A")}')

            with col2:
                st.metric("NIST CSF Function", mapping_data.get("nist_function", "N/A"))
                st.info(f'**Category:** {mapping_data.get("nist_category", "N/A")}')

            with col3:
                st.markdown("### Remediation Suggestion")
                st.success(mapping_data.get("remediation_suggestion", "N/A"))

            st.markdown("---")


# Run the app locally in your VS Code terminal with: streamlit run app.py
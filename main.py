from dotenv import load_dotenv
import gradio as gr
import os, json
import requests
import urllib3

def checkEnvVariable(var_name):
    """Check if an environment variable is set and return its value."""
    env_var  = os.environ.get(var_name)
    if not env_var: 
        return "Missing the environment variable: " + var_name
    return env_var

def ai_summary(LMAAS_URL, LMAAS_KEY, MODEL, fw_data):
    """Get AI-generated summary of the firewall data."""

    lmaas_headers = {
        'Authorization': f'Bearer {LMAAS_KEY}',
        'Content-Type': 'application/json'
    }
    summary_payload = {
        'model': MODEL,
        'messages': [
            {'role': 'system', 'content': 'You are a network NOC assistant. Reply in 5-8 short bullet points, plain English, no code blocks.'},
            {'role': 'user', 'content': f"Summarize these IPSec tunnel states for a manager:\n\n{json.dumps(fw_data)}"}
        ],
        'temperature': 0.2,
        'stream': True
    }
    try:
        response = requests.post(LMAAS_URL, headers=lmaas_headers, json=summary_payload, timeout=30, stream=True)
        response.raise_for_status()
        analysis_text = ""
        for line in response.iter_lines():
            if line:
                decoded_line = line.decode('utf-8')
                
                # We are looking for lines that start with "data: "
                if decoded_line.startswith('data: '):
                    data_str = decoded_line[len('data: '):].strip()
                    
                    # Check for the end-of-stream signal
                    if data_str == '[DONE]':
                        print("\n--- Stream finished ---")
                        break
                        
                    # Try to parse the JSON chunk
                    try:
                        chunk = json.loads(data_str)
                        
                        # Check if the chunk contains the content
                        if 'choices' in chunk and len(chunk['choices']) > 0:
                            delta = chunk['choices'][0].get('delta', {})
                            content_chunk = delta.get('content')
                            
                            if content_chunk:
                                # Add the new text chunk to our full response
                                analysis_text += content_chunk
                                
                                # Yield the *entire* updated text so far
                                yield analysis_text
                                
                    except json.JSONDecodeError:
                        print(f"\nError decoding JSON chunk: {data_str}")
                        
        # This return is no longer strictly needed for the happy path,
        # but yield ensures the final state is sent.
        yield analysis_text
        
    except Exception as e:
        print(f"Failed to get AI summary: {e}")

def firewall_data(FW_HOST, FW_TOKEN):
    """Fetch firewall data from the FortiGate API."""

    url = f"{FW_HOST}/api/v2/monitor/vpn/ipsec/select"
    fw_header = fw_headers = {'Authorization': f'Bearer {FW_TOKEN}'}
    raw_data = {}
    try:
        response = requests.get(url, headers=fw_headers, verify=False, timeout=10)
        response.raise_for_status() # Exit on HTTP error
        raw_data = response.json() # Try to parse
        return raw_data
    except requests.RequestException as e:
        print("Unexpected error occured while reading the firewall logs")
        return
    except json.JSONDecodeError:
        print("FortiGate response was not valid JSON.")
        return

def ai_proposed_actions(LMAAS_URL, LMAAS_KEY, MODEL, raw_data):
    """Placeholder for AI proposed actions function."""
    down_tunnels_list = []
    try:
        if raw_data.get('results'):
            for result in raw_data['results']:
                if result.get('proxyid'):
                    for proxy in result['proxyid']:
                        if proxy.get('status') == 'down':
                            name = result.get('name') or result.get('p2name') or "unknown"
                            down_tunnels_list.append(name)
        
        # Get unique list
        down_tunnels_list = sorted(list(set(down_tunnels_list)))
        down_count = len(down_tunnels_list)
    except Exception as e:
        print(f"Failed to parse raw JSON for down tunnels: {e}")
        down_count = 0

    # ---------- 5) Ask AI to PROPOSE ACTIONS ----------
    actions_json_list = []
    if down_count > 0:
        down_csv = ",".join(down_tunnels_list)
        
        lmaas_headers = {
        'Authorization': f'Bearer {LMAAS_KEY}',
        'Content-Type': 'application/json'
        }
        # Using Python's multiline string for the prompt
        action_prompt = """
            Return ONLY strict JSON with this schema:
            {
            "actions": [
                {
                "method": "POST",
                "url": "",
                "payload": {},
                "why": "",
                "risk": "low|medium|high"
                }
            ]
            }
            Rules:
            - Only suggest safe, non-disruptive actions like notifications.
            - Prefer a single POST to a notify endpoint containing an array of tunnel names.
            - Do NOT suggest config changes, reboots, or resets.
            - If unsure, return {"actions":[]}.
            """
        action_payload = {
                'model': MODEL,
                'messages': [
                    {'role': 'system', 'content': action_prompt},
                    {'role': 'user', 'content': f"Tunnels down: {down_csv}\nHere is the raw JSON (for reference): {json.dumps(raw_data)}"}
                ],
                'temperature': 0.1,
                'stream': True
            }
            
        try:
                response = requests.post(LMAAS_URL, headers=lmaas_headers, json=action_payload, timeout=30, stream=True)
                response.raise_for_status()
                analysis_text = ""
                for line in response.iter_lines():
                    if line:
                        decoded_line = line.decode('utf-8')
                        
                        if decoded_line.startswith('data: '):
                            data_str = decoded_line[len('data: '):].strip()
                            
                            if data_str == '[DONE]':
                                break
                            
                            try:
                                chunk = json.loads(data_str)
                                if 'choices' in chunk and len(chunk['choices']) > 0:
                                    delta = chunk['choices'][0].get('delta', {})
                                    content_chunk = delta.get('content')
                                    
                                    if content_chunk:
                                        # Add the new JSON chunk
                                        analysis_text += content_chunk
                                        # Yield the *entire* updated JSON string so far
                                        yield analysis_text
                                        
                            except json.JSONDecodeError:
                                print(f"\nError decoding JSON chunk: {data_str}")
                                
                # This final yield ensures the complete text is sent
                yield analysis_text 
            
        except Exception as e:
            print(f"Could not stream AI action response: {e}")
            yield "{ \"error\": \"Could not get AI actions. Check logs.\" }"
        # --- END OF REPLACEMENT ---

    else:
        print("No tunnels are DOWN — no actions needed.")
        # Yield a string to inform the UI
        yield "No down tunnels. No actions proposed."
       
def handleApproval(answer, current_analysis_text):
    """Handles the user's approval and appends the result to the main output."""
    answer = answer.strip().lower()
    
    # This is the "base" text to add to
    base_text = current_analysis_text
    
    if answer in ['y', 'yes']:
        # First, yield the "Received" message
        received_message = "\n\n ## Approval received"
        yield base_text + received_message
        
        # --- This is where you would perform the real action ---
        # print("Calling the real API action now...")
        # try:
        #    requests.post(...)
        #    action_status = "Successfully performed action."
        # except Exception as e:
        #    action_status = f"Action failed: {e}"
        # ---
        
        # For this demo, we'll just pretend:
        action_status = "## Performing action......" # This is what you asked for
        
        # Now, yield the *next* update
        yield base_text + received_message + f"\n**{action_status}**"
        
    elif answer in ['n', 'no']:
        yield base_text + "\n\n---\n\n### Approval denied. No action Taken."
    else:
        yield base_text + "\n\n---\n\n### Invalid input. No action Taken."

def analyzeFW():
    """Main function to analyze the firewall data and interact with AI."""
     #checking whether the environment variables exists.
    try:
        FW_HOST = checkEnvVariable("FW_HOST")
        FW_TOKEN = checkEnvVariable("FW_TOKEN")
        LMAAS_URL = checkEnvVariable("LMAAS_URL")
        LMAAS_KEY = checkEnvVariable("LMAAS_KEY")
        MODEL = checkEnvVariable("MODEL")
    except error as e:
        print ("Problem in retrieving env variables")
        return
    
    #Loading optional environment variables 
    APPROVAL_MODE = os.environ.get('APPROVAL_MODE', 'ask')
    APPROVAL_TIMEOUT = int(os.environ.get('APPROVAL_TIMEOUT', 30))
    DRY_RUN = os.environ.get('DRY_RUN', '0')
    ALLOW_NONDEMO = os.environ.get('ALLOW_NONDEMO', '0')

    ACTION_URL_DEFAULT = f"{FW_HOST}/api/v2/trigger/notify"
    ACTION_URL = os.environ.get('ACTION_URL', ACTION_URL_DEFAULT)

    # Query FortiGate firewall
    fw_data = firewall_data(FW_HOST, FW_TOKEN)
    if not fw_data:
        yield "Failed to retrieve firewall data."
        return 
    
    #print (json.dumps(fw_data, indent=2))

    # Ask AI for human Summary
    summary_stream = ai_summary(LMAAS_URL, LMAAS_KEY, MODEL, fw_data)
    
    final_summary_text = "" # This will store the *final* summary
    summary_header = "## Tunnel Health Analysis\n"
    yield summary_header # Show the header immediately

    for chunk in summary_stream:
        final_summary_text = chunk # Store the latest full text
        yield summary_header + final_summary_text # Yield the header + the latest text

    # --- 4. Stream Proposed Actions ---
    
    # 'final_summary_text' is now a finished, static string.
    # We create a new "base" by combining it with the *next* header.
    
    action_header = "\n\n## Proposed Actions\n"
    
    # This is the "prefix" that will not change.
    base_output = summary_header + final_summary_text + action_header
    
    # Yield the base to show the new header
    yield base_output 

    action_stream = ai_proposed_actions(LMAAS_URL, LMAAS_KEY, MODEL, fw_data)
    
    final_action_json = "" # This will store the *final* action JSON
    for action_chunk in action_stream:
        final_action_json = action_chunk # Store the latest full chunk
        
        # Rebuild the *entire* output every time from its parts:
        # [Part 1: The static base] + [Part 2: The formatted streaming chunk]
        yield base_output + "```json\n" + final_action_json + "\n```"
   
    # Request for approval
    if "No actions" not in final_action_json and "error" not in final_action_json:
        final_output = base_output + "```json\n" + final_action_json + "\n```"
        final_output += "\n\n---\n\nPlease review the actions and provide approval in the box below."
        yield final_output
    
    # Perform the Action
   

def main():
    """Entry point of the code. It is arranged in sequential manner of the process"""
   
    #loading the environment varibales: 
    load_dotenv()
    urllib3.disable_warnings()
    custom_theme = gr.themes.Ocean().set(
    button_primary_background_fill="#ADC937",
    button_primary_text_color="white",
    body_background_fill="#ADC937",  
    )
    custom_css = """
    #certin-logo img {
    width: 80px !important;
    height: 80px !important;
    object-fit: contain;
    }

     #redhat-logo img{
     width: 100px !important;
     height: 100px !important;
     object-fit: contain;
     }
"""
    with gr.Blocks(theme=custom_theme, css=custom_css) as demo:
        gr.Markdown("# IPSec Tunnel AI Agent POC\n")
        with gr.Row(equal_height=True, ):
            gr.Image(value="https://www.logo.wine/a/logo/Red_Hat/Red_Hat-Logo.wine.svg", elem_id="redhat-logo", width=80, height=80, show_download_button=False, show_label=False, scale=1)
            gr.Image(value="https://www.presentations.gov.in/wp-content/uploads/2020/06/Preview-21.png", elem_id="certin-logo", width=80, height=80, show_download_button=False, show_label=False, scale=1)
            gr.Markdown("## CertIn & Red Hat ")
        out = gr.Markdown(label="Analysis Result")
        with gr.Row(equal_height=True):
            with gr.Column(scale=3):
                inp = gr.Textbox(placeholder="Provide your approval...",label="Approval", lines=1)
                submit = gr.Button("Submit", variant="huggingface", size="lg")
                submit.click(fn=handleApproval, inputs=[inp, out], outputs=[out])
            analyze = gr.Button("Analyze Logs", variant="primary", scale=1)
            analyze.click(fn = analyzeFW, outputs = out, api_name="analyse" )
        

    demo.launch()


if __name__ == "__main__":
    main()

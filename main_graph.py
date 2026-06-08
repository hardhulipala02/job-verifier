from typing import TypedDict
from langgraph.graph import StateGraph, END
import parser  
import llm_agent 

class AgentState(TypedDict):
    email_file_path: str
    dmarc_status: str
    email_text: str
    final_verdict: dict

def run_parser_node(state: AgentState):
    print("--- RUNNING NODE 1: PARSER ---")
    
    parsed_msg, sender = parser.parse_email_basics(state["email_file_path"])
    security_data = parser.extract_security_headers(parsed_msg)

    email_text = "" 
    if parsed_msg.is_multipart():
        email_text = parsed_msg.get_payload()[0].get_payload()
    else:
        email_text = parsed_msg.get_payload()
    
    return {
        "dmarc_status": security_data["dmarc"],
        "spf_status": security_data["spf"],
        "dkim_status": security_data["dkim"],
        "sender": sender,  
        "email_text": str(email_text)
    }
    

def run_llm_node(state: AgentState):
    print("--- RUNNING NODE 2: LLM BRAIN ---")
    
    scorecard = llm_agent.evaluate_email_behavior(state["email_text"])
    
    return {"final_verdict": scorecard}


def route_based_on_security(state: AgentState):
    print("--- ROUTING CHECK ---")
    if state["dmarc_status"] == "fail":
        print("DMARC failed! Spoof detected. Ending workflow.")
        return "end_workflow"
    else:
        print("DMARC passed. Sending to LLM for behavioral check.")
        return "send_to_llm"


workflow = StateGraph(AgentState)

workflow.add_node("parser_agent", run_parser_node)
workflow.add_node("llm_agent", run_llm_node)

workflow.set_entry_point("parser_agent")

workflow.add_conditional_edges(
    "parser_agent", 
    route_based_on_security, 
    {
        "end_workflow": END,
        "send_to_llm": "llm_agent"
    }
)

workflow.add_edge("llm_agent", END)

app = workflow.compile()

if __name__ == "__main__":
    print("\nStarting Job Scam Intelligence Network...")
    
    initial_state = {"email_file_path": "test_email.eml"}
    
    result = app.invoke(initial_state)
    print("\n--- FINAL GRAPH STATE ---")
    print(result)
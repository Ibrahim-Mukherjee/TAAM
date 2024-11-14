from transformers import AutoModelForCausalLM, AutoTokenizer
import torch
import ccm  # Python ACT-R implementation
import random

# Initialize OpenELM models
model_names = ["apple/OpenELM-270M", "apple/OpenELM-450M", "apple/OpenELM-1_1B", "apple/OpenELM-3B"]
models = {name: AutoModelForCausalLM.from_pretrained(name, trust_remote_code=True) for name in model_names}
tokenizer = AutoTokenizer.from_pretrained("apple/OpenELM-270M")

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
for model in models.values():
    model.to(device)

class ThreatAllocator(ccm.Model):
    def __init__(self):
        self.goal = ccm.Model(state='idle')
        self.threat_memory = ccm.Buffer()
        self.model_selection = ccm.Buffer()

    def allocate_threat(self, threat):
        self.goal.state = 'allocating'
        self.threat_memory.set(threat)
        self.run()
        return self.model_selection.chunk['model']

    def production_rules(self):
        def analyze_threat(self):
            if self.goal.state == 'allocating' and self.threat_memory.chunk:
                threat = self.threat_memory.chunk
                if 'malware' in threat['type']:
                    self.model_selection.set('model: OpenELM-3B')
                elif 'network' in threat['type']:
                    self.model_selection.set('model: OpenELM-1_1B')
                elif 'social_engineering' in threat['type']:
                    self.model_selection.set('model: OpenELM-450M')
                else:
                    self.model_selection.set('model: OpenELM-270M')
                self.goal.state = 'idle'

        return analyze_threat
    
    class SLMCluster:
    def __init__(self, models, tokenizer):
        self.models = models
        self.tokenizer = tokenizer
        self.allocator = ThreatAllocator()

    def process_threat(self, threat):
        model_name = self.allocator.allocate_threat(threat)
        model = self.models[model_name]
        
        prompt = f"Analyze the following cyber threat: {threat['description']}"
        inputs = self.tokenizer(prompt, return_tensors="pt").to(device)
        
        with torch.no_grad():
            outputs = model.generate(**inputs, max_length=200)
        
        return self.tokenizer.decode(outputs[0], skip_special_tokens=True)

# Initialize the SLM Cluster
slm_cluster = SLMCluster(models, tokenizer)

# Example threats
threats = [
    {"type": "malware", "description": "New ransomware strain targeting healthcare systems"},
    {"type": "network", "description": "Unusual traffic patterns suggesting DDoS attack"},
    {"type": "social_engineering", "description": "Phishing campaign impersonating major bank"},
    {"type": "unknown", "description": "Unclassified anomaly in system logs"}
]

# Process threats
for threat in threats:
    analysis = slm_cluster.process_threat(threat)
    print(f"Threat: {threat['description']}")
    print(f"Analysis: {analysis}\n")
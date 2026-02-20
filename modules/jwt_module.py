from .base import BaseModule
import os
import json
import base64

class JwtModule(BaseModule):
    def run(self, targets):
        # Native python implementation for basic JWT analysis
        results = []
        for target in targets:
            # Placeholder for JWT extraction logic
            # In a real scenario, this would intercept traffic or parse config
            pass
            
        return results

    def decode_jwt(self, token):
        try:
            header, payload, signature = token.split('.')
            decoded_header = base64.urlsafe_b64decode(header + "==").decode('utf-8')
            decoded_payload = base64.urlsafe_b64decode(payload + "==").decode('utf-8')
            return json.loads(decoded_header), json.loads(decoded_payload)
        except Exception as e:
            return None, None

    def parse_results(self, data):
        normalized_file = os.path.join(self.normalized_output_dir, "jwt_analysis.csv")
        with open(normalized_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            for item in data:
                writer.writerow([item.get('token'), item.get('alg'), item.get('payload')])

from prediction.live_mapper import map_live_flow
from prediction.predict import IntrusionPredictor

# Fake live packet data from a sniffer
fake_live_flow = {
    'Flow Duration': 15000,
    'Protocol': 'TCP',
    'Total Fwd Packets': 10,
    'Total Backward Packets': 5,
    'Total Length of Fwd Packets': 500,
    'Total Length of Bwd Packets': 250,
}

# 1. Map it
mapped_df = map_live_flow(fake_live_flow)

# 2. Predict
predictor = IntrusionPredictor().load()
result = predictor.predict(mapped_df)

# 3. Print result
print(f"Prediction: {result['label']} (Confidence: {result['confidence']:.2%})")
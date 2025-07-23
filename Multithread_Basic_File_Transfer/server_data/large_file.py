#!/usr/bin/env python3
"""
Arquivo de teste para demonstrar upload/download
Este arquivo é maior e mais complexo para testar o sistema de chunks.
"""

import json
import random
import time

def generate_test_data():
    """Gera dados de teste complexos."""
    data = {
        "users": [],
        "products": [],
        "orders": [],
        "metadata": {
            "generated_at": time.time(),
            "version": "1.0.0",
            "total_records": 1000
        }
    }
    
    # Gerar usuários
    for i in range(100):
        user = {
            "id": i + 1,
            "name": f"User_{i+1}",
            "email": f"user{i+1}@example.com",
            "age": random.randint(18, 80),
            "active": random.choice([True, False]),
            "preferences": {
                "theme": random.choice(["dark", "light"]),
                "language": random.choice(["en", "pt", "es", "fr"]),
                "notifications": random.choice([True, False])
            }
        }
        data["users"].append(user)
    
    # Gerar produtos
    categories = ["Electronics", "Clothing", "Books", "Home", "Sports"]
    for i in range(200):
        product = {
            "id": i + 1,
            "name": f"Product_{i+1}",
            "category": random.choice(categories),
            "price": round(random.uniform(10.0, 1000.0), 2),
            "in_stock": random.randint(0, 100),
            "description": f"This is a description for product {i+1}. " * 3,
            "tags": [f"tag{j}" for j in range(random.randint(1, 5))]
        }
        data["products"].append(product)
    
    # Gerar pedidos
    for i in range(300):
        order = {
            "id": i + 1,
            "user_id": random.randint(1, 100),
            "product_ids": [random.randint(1, 200) for _ in range(random.randint(1, 5))],
            "total": round(random.uniform(50.0, 2000.0), 2),
            "status": random.choice(["pending", "processing", "shipped", "delivered"]),
            "created_at": time.time() - random.randint(0, 86400 * 30),
            "shipping_address": {
                "street": f"Street {i+1}",
                "city": f"City {i%20}",
                "zipcode": f"{random.randint(10000, 99999)}",
                "country": random.choice(["USA", "Brazil", "Canada", "UK"])
            }
        }
        data["orders"].append(order)
    
    return data

if __name__ == "__main__":
    print("Generating test data...")
    test_data = generate_test_data()
    
    # Converter para JSON com indentação para um arquivo maior
    json_data = json.dumps(test_data, indent=2, ensure_ascii=False)
    
    print(f"Generated {len(json_data)} characters of test data")
    print(f"Users: {len(test_data['users'])}")
    print(f"Products: {len(test_data['products'])}")
    print(f"Orders: {len(test_data['orders'])}")
    
    # Salvar arquivo
    with open("large_test_data.json", "w", encoding="utf-8") as f:
        f.write(json_data)
    
    print("Test data saved to large_test_data.json")

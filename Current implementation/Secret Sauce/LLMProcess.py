import json
import re
import contractions
from pathlib import Path
from docx import Document
from spellchecker import SpellChecker
from sentence_transformers import SentenceTransformer

# === Core Text I/O ===
def read_file(file_path):
    ext = Path(file_path).suffix.lower()
    if ext == '.txt':
        return Path(file_path).read_text(encoding='utf-8')
    elif ext == '.docx':
        doc = Document(file_path)
        return "\n".join(p.text for p in doc.paragraphs)
    elif ext == '.md':
        return Path(file_path).read_text(encoding='utf-8')
    else:
        raise ValueError(f"Unsupported format: {ext}")

# === Chunking ===
def chunk_text(text, max_words=500, overlap=50):
    words = text.split()
    chunks = []
    start = 0
    while start < len(words):
        end = min(start + max_words, len(words))
        chunk = " ".join(words[start:end])
        chunks.append(chunk)
        start = end - overlap
    return chunks

# === Spell Correction ===
def correct_spelling(text):
    spell = SpellChecker()
    words = text.split()
    corrected = [spell.correction(word) or word for word in words]
    return ' '.join(corrected)

# === LLM-Oriented Cleaning ===
def preprocess_for_llm(text):
    text = contractions.fix(text)
    text = text.lower()
    text = re.sub(r'[^a-z\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return correct_spelling(text)

# === JSONL Export ===
def export_to_jsonl(chunks, output_path, mode="instruct"):
    with open(output_path, 'w', encoding='utf-8') as f:
        for chunk in chunks:
            data = {
                "prompt": f"Summarize the following:\n\n{chunk}",
                "completion": "" if mode == "instruct" else None
            } if mode == "instruct" else {"text": chunk}
            f.write(json.dumps(data) + "\n")

# === Optional Embedding ===
def embed_chunks(chunks, model_name='all-MiniLM-L6-v2'):
    model = SentenceTransformer(model_name)
    return model.encode(chunks)

# === CLI-Like Runner ===
def run_pipeline(input_path, output_jsonl, embed=False):
    print(f"📂 Reading: {input_path}")
    text = read_file(input_path)
    print(f"🧹 Preprocessing text...")
    preprocessed = preprocess_for_llm(text)
    print(f"📚 Chunking...")
    chunks = chunk_text(preprocessed)
    print(f"📝 Exporting to: {output_jsonl}")
    export_to_jsonl(chunks, output_jsonl)
    if embed:
        print("🔍 Generating embeddings...")
        vectors = embed_chunks(chunks)
        print(f"✅ Generated {len(vectors)} vectors.")
        return vectors
    print("✅ Pipeline complete.")

# Example use
if __name__ == "__main__":
    run_pipeline("my_file.docx", "formatted_output.jsonl", embed=True)
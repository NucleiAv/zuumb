class FakeEmbedding:
    """Deterministic stand-in for app.correlation.similarity's real embedding
    model: a bag-of-words indicator vector over the batch's own vocabulary,
    no network call, no ONNX download. Text that shares words scores similar,
    text that shares nothing scores ~0."""
    def embed(self, texts):
        import numpy as np
        vocab = sorted({w for t in texts for w in t.lower().split()})
        idx = {w: i for i, w in enumerate(vocab)}
        vecs = np.zeros((len(texts), max(len(vocab), 1)))
        for row, t in zip(vecs, texts):
            for w in t.lower().split():
                row[idx[w]] = 1.0
        return list(vecs)

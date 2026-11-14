"""Report figures (wiggle/figures.py), from a small synthetic pooled record. No artifact is read."""

import unittest

from wiggle.figures import birth_figure, ladder_figure, layers_figure


def _cell(hits, total):
    return {"hits": hits, "total": total, "rate": hits / total, "wilson": {"low": 0.0, "high": min(1.0, hits / total + 0.05)}}


def _pooled():
    layer = lambda asr: {"per_model": {"m1": {"asr": _cell(0, 150), "heldout": _cell(230, 234)}, "m2": {"asr": _cell(asr, 150), "heldout": _cell(200, 234)}}}
    arm = {"alone": {name: layer(18 if name != "d" else 0) for name in "abcde"}, "stacked": {"a+b+c+d+e": layer(0)}}
    level = lambda name, blocked, kept: {
        "level": 0, "name": name,
        "per_model": {model: {"attack_block": _cell(blocked, 150), "heldout": _cell(kept, 234)} for model in ("m1", "m2")},
    }
    return {
        "models": [{"model": "m1"}, {"model": "m2"}],
        "layers": {"patched": arm, "vulnerable": arm},
        "ladder": [level("L0 schema", 132, 232), level("L3 needed dirs", 150, 170)],
    }


class FigureTests(unittest.TestCase):
    def test_layers_figure_names_every_layer_and_every_model_count(self):
        svg = layers_figure(_pooled())
        self.assertTrue(svg.startswith("<svg"))
        for label in ("(a) zgScanner", "(d) task policy", "all five, stacked", "m1", "m2"):
            self.assertIn(label, svg)
        self.assertIn("18/150", svg)
        # The attack panel fits the data instead of a 0-100% axis.
        self.assertIn("0-20%", svg)

    def test_ladder_figure_starts_its_axis_at_a_stated_floor(self):
        svg = ladder_figure(_pooled())
        self.assertIn("axis starts at 80%", svg)
        self.assertIn("blocked 150/150, held-out 170/234", svg)

    def test_birth_figure_shows_the_three_counts(self):
        record = {
            "model": "m2",
            "widened_beyond_clean": {"hits": 46, "total": 390},
            "baseline": {"repeat_added_beyond_clean": {"hits": 8, "total": 78}},
            "widened_toward_target": {"hits": 0, "total": 390},
        }
        svg = birth_figure(record)
        for count in ("46/390", "8/78", "0/390"):
            self.assertIn(count, svg)


if __name__ == "__main__":
    unittest.main()

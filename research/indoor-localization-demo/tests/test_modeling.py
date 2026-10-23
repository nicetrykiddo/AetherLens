import unittest

from modeling import make_classifier, synthetic_data


class SyntheticDataTests(unittest.TestCase):
    def test_shape_labels_and_signal_range(self):
        features, labels = synthetic_data(seed=7, n_per_room=5)
        self.assertEqual(features.shape, (20, 7))
        self.assertEqual(labels.shape, (20,))
        self.assertEqual(set(labels), {"Room 1", "Room 2", "Room 3", "Room 4"})
        self.assertTrue((features >= -100).all().all())
        self.assertTrue((features <= -25).all().all())

    def test_same_seed_is_reproducible(self):
        first_x, first_y = synthetic_data(seed=123, n_per_room=4)
        second_x, second_y = synthetic_data(seed=123, n_per_room=4)
        self.assertTrue(first_x.equals(second_x))
        self.assertTrue(first_y.equals(second_y))

    def test_rejects_too_few_samples(self):
        with self.assertRaises(ValueError):
            synthetic_data(n_per_room=1)


class ClassifierTests(unittest.TestCase):
    def test_fitted_model_predicts_valid_room_and_normalized_scores(self):
        features, labels = synthetic_data(seed=42, n_per_room=12)
        model = make_classifier(max_depth=5, seed=42)
        model.fit(features, labels)
        prediction = model.predict(features.iloc[[0]])[0]
        scores = model.predict_proba(features.iloc[[0]])[0]
        self.assertIn(prediction, set(labels))
        self.assertAlmostEqual(float(scores.sum()), 1.0, places=6)

    def test_rejects_invalid_depth(self):
        with self.assertRaises(ValueError):
            make_classifier(max_depth=0)


if __name__ == "__main__":
    unittest.main()

def compute_metrics(predictions: list[dict],
                    ground_truth: list[dict]) -> dict:
    tp = fp = fn = tn = 0
    for pred, gt in zip(predictions, ground_truth):
        pred_label = pred["verdict"] == "actionable"
        gt_label   = gt["verdict"]  == "actionable"
        if pred_label and gt_label:     tp += 1
        elif pred_label and not gt_label: fp += 1
        elif not pred_label and gt_label: fn += 1
        else:                           tn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) \
                if (precision + recall) > 0 else 0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        "actionable_f1": round(f1, 3),
        "false_positive_rate": round(fpr, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3)
    }

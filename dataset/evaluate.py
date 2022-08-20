import json
import os
from copy import deepcopy

import pandas as pd
from sklearn.metrics import confusion_matrix

DATA_FOLDER = "results"


class EvaluationCell(object):
    @classmethod
    def from_dict(cls, input_dict):
        return cls(
                input_dict['tp'], input_dict['fp'], input_dict['fn'], input_dict['precision'], input_dict['recall']
        )

    def __init__(self, TP=0, FP=0, FN=0, precision=0.0, recall=0.0):
        self.tp = TP
        self.fp = FP
        self.fn = FN
        self.precision = round(precision, 4)
        self.recall = round(recall, 4)

    def __str__(self):
        return f"{self.tp}\t{self.fp}\t{self.fn}\t{self.precision}\t{self.recall}"

    def to_dict(self):
        return {"tp": int(self.tp), "fp": int(self.fp), "fn": int(self.fn),
                "precision": float(self.precision), "recall": float(self.recall)}

    def __add__(self, other):
        if isinstance(other, EvaluationCell):
            TP, FP, FN = self.tp + other.tp, self.fp + other.fp, self.fn + other.fn,
            return EvaluationCell(
                    TP, FP, FN,
                    TP / (TP + FP),
                    TP / (TP + FN)
            )


def get_dataset_data_frame():
    objs = json.load(fp=open(os.path.join(".", "ground_truth.json")))
    RES_DF = []
    for obj in objs:
        RES_DF.append({
                "cve_id": obj['cve_id'],
                "version": obj['version'],
                "is_affected": 1 if obj['is_affected'] == "affected" else 0,
        })
    return pd.DataFrame(RES_DF)


def get_other_data_frame(name):
    objs = json.load(fp=open(os.path.join(DATA_FOLDER, f"{name}.json")))
    RES_DF = []
    for obj in objs:
        RES_DF.append(obj)
    return pd.DataFrame(RES_DF)


afv_result = get_other_data_frame("afv")
afv_result_unaffected = deepcopy(afv_result)
afv_result["is_affected"] = afv_result["is_affected"].apply(lambda x: 0 if x == 2 else x)
afv_result_unaffected["is_affected"] = afv_result_unaffected["is_affected"].apply(lambda x: 0 if x == 2 else ~x + 2)

v0finder_result = get_other_data_frame("v0finder")

redebug_result = get_other_data_frame("redebug")

vszz_result = get_other_data_frame("vszz")
vszz_result_unaffected = deepcopy(vszz_result)
vszz_result_unaffected["is_affected"] = vszz_result_unaffected["is_affected"].apply(lambda x: 0 if x == 2 else ~x + 2)

vszz_plus_result = get_other_data_frame("vszz++")
vszz_plus_result_unaffected = deepcopy(vszz_plus_result)
vszz_plus_result_unaffected["is_affected"] = vszz_plus_result_unaffected["is_affected"].apply(
        lambda x: 0 if x == 2 else ~x + 2)

dataset_result = get_dataset_data_frame()
dataset_result_unaffected = deepcopy(dataset_result)
dataset_result_unaffected["is_affected"] = dataset_result_unaffected["is_affected"].apply(lambda x: ~x + 2)

affected_number = dataset_result[dataset_result['is_affected'] == 1].count().iloc[-1]
unaffected_number = dataset_result[dataset_result['is_affected'] == 0].count().iloc[-1]


def cross(_sub_gt_df, _sub_result_df):
    _sub_gt_df.sort_values(["cve_id", "version"], inplace=True)
    _sub_result_df.sort_values(["cve_id", "version"], inplace=True)

    cm = confusion_matrix(_sub_gt_df['is_affected'], _sub_result_df['is_affected'])
    FN = cm[1][0]
    TP = cm[1][1]
    FP = cm[0][1]
    return EvaluationCell(TP, FP, FN, TP / (TP + FP), TP / (TP + FN))


ceil_v0finder_affected = cross(dataset_result, v0finder_result)
ceil_redebug_affected = cross(dataset_result, redebug_result)

ceil_vszz_affected = cross(dataset_result, vszz_result)
ceil_vszz_puls_affected = cross(dataset_result, vszz_plus_result)
ceil_afv_affected = cross(dataset_result, afv_result)

ceil_vszz_unaffected = cross(dataset_result_unaffected, vszz_result_unaffected)
ceil_vszz_puls_unaffected = cross(dataset_result_unaffected, vszz_plus_result_unaffected)
ceil_afv_unaffected = cross(dataset_result_unaffected, afv_result_unaffected)

ceil_vszz_all = ceil_vszz_affected + ceil_vszz_unaffected
ceil_vszz_puls_all = ceil_vszz_puls_affected + ceil_vszz_puls_unaffected
ceil_afv_all = ceil_afv_affected + ceil_afv_unaffected

print(f"""
Effectiveness Results of AFV. (RQ1)

{affected_number}\t{ceil_afv_affected}\n{unaffected_number}\t{ceil_afv_unaffected}\n{affected_number + unaffected_number}\t{ceil_afv_all}


Comparison Results with V-SZZ. (RQ2)

{ceil_afv_affected}\n{ceil_vszz_affected}\n{ceil_vszz_puls_affected}

{ceil_afv_unaffected}\n{ceil_vszz_unaffected}\n{ceil_vszz_puls_unaffected}

{ceil_afv_all}\n{ceil_vszz_all}\n{ceil_vszz_puls_all}


Comparison Results with ReDebug and V0Finder in Identifying Affected Versions. (RQ2)

{ceil_afv_affected}\n{ceil_redebug_affected}\n{ceil_v0finder_affected}

""")

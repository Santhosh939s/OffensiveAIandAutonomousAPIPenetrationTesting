path = r"S:\UROP\offensive AI and autonomous APi penetration testing\scratch\build_rebuiltv5_pilot_dataset.py"
content = open(path, "r", encoding="utf-8").read()
new_content = content.replace("//4", "//5")

old_split = """    # Flatten items of this task
    task_items = [r for r in all_records if r["task_id"] == task_id]
    rng.shuffle(task_items)
    
    t_records = task_items[:n_train]
    v_records = task_items[n_train:n_train+n_val]
    e_records = task_items[n_train+n_val:n_train+n_val+n_test]
    
    for r in t_records: r["split"] = "train"
    for r in v_records: r["split"] = "val"
    for r in e_records: r["split"] = "test"
    
    train_records.extend(t_records)
    val_records.extend(v_records)
    test_records.extend(e_records)"""

new_split = """    n_train_f = n_train // 5
    n_val_f = n_val // 5
    n_test_f = n_test // 5
    
    train_f_set = set(families[:n_train_f])
    val_f_set = set(families[n_train_f:n_train_f+n_val_f])
    test_f_set = set(families[n_train_f+n_val_f:n_train_f+n_val_f+n_test_f])
    
    for f_name in train_f_set:
        for r in task_family_map[task_id][f_name]:
            r["split"] = "train"
            train_records.append(r)
    for f_name in val_f_set:
        for r in task_family_map[task_id][f_name]:
            r["split"] = "val"
            val_records.append(r)
    for f_name in test_f_set:
        for r in task_family_map[task_id][f_name]:
            r["split"] = "test"
            test_records.append(r)"""

assert old_split in new_content, "Old split snippet not found in file!"
new_content = new_content.replace(old_split, new_split)
open(path, "w", encoding="utf-8").write(new_content)
print("Successfully updated build_rebuiltv5_pilot_dataset.py with atomic family splitting!")

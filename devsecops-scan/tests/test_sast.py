from devsecops_scan.sast import scan_sast


def test_python_and_js_rules() -> None:
    python = "\n".join(
        [
            "literal_eval(blob)",
            "eval(user_input)",
            "exec(user_input)",
            "subprocess.run(cmd, shell=True)",
            "os.system(cmd)",
            "yaml.load(data)",
            "yaml.load(data, Loader=yaml.SafeLoader)",
            "yaml.safe_load(data)",
            "pickle.loads(blob)",
            "requests.get(url, verify=False)",
            'cursor.execute(f"SELECT {user_id}")',
            'cursor.execute("SELECT %s", (user_id,))',
            'cursor.execute("SELECT " + user_id)',
            'algorithms = ["none"]',
        ]
    )
    ids = [item.rule_id for item in scan_sast(python, "app.py")]
    assert "python-eval" in ids
    assert ids.count("python-eval") == 1
    assert "python-exec" in ids
    assert "subprocess-shell" in ids
    assert "os-system" in ids
    assert "yaml-unsafe-load" in ids
    assert ids.count("yaml-unsafe-load") == 1
    assert "insecure-pickle" in ids
    assert "tls-verify-disabled" in ids
    assert "sql-string-execute" in ids
    assert "sql-string-concat" in ids
    assert "jwt-algorithm-none" in ids
    javascript = "element.innerHTML = body\ndangerouslySetInnerHTML\neval(code)\n"
    js_ids = {item.rule_id for item in scan_sast(javascript, "app.tsx")}
    assert js_ids == {"innerhtml-assign", "react-dangerous-html", "js-eval"}

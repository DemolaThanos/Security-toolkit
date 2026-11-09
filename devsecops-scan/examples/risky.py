"""Example input for devsecops-scan. It is supposed to produce a finding."""

user = input()
result = eval(user)  # noqa: S307 - example of the python-eval rule
print(result)

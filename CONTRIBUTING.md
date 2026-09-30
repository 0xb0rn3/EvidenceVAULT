# Contribute to EvidenceVault

Keep the code in Python. Use the standard library for runtime features.
Use a small function for each task. Use names that describe the task.

## Write clear text

Use the ASD-STE100 writing style for comments, help text, reports, and documentation.
Use short sentences. Use one meaning for each term.
Use the active voice. Give one instruction per step.
Do not use contractions.

Keep an instruction within 20 words.
Keep a descriptive sentence within 25 words when practical.
Define a technical term before you use it.

The project uses these technical terms:

| Term | Meaning |
|---|---|
| Archive | One file that contains the case files and their manifest. |
| Manifest | A list of file paths, sizes, hashes, and recorded times. |
| Hash | A value calculated from file contents. |
| Codec | A method that converts bytes to an encoded form and back. |
| Worker | A thread that processes a file task. |
| Run | One command operation and its result. |
| File signature | Known bytes that can indicate a file type. |
| Audit database | The local SQLite file that stores runs and file actions. |

## Change the code

1. Create a branch for the change.
2. Read the relevant module and its tests.
3. Keep source files unchanged unless the operator selects an in-place action.
4. Reject an unsafe input before an output write.
5. Add a test for each file safety fix.
6. Run the tests.
7. Update the README if command behavior changes.

Use these checks:

~~~bash
python -m compileall -q evidencevault Evidencevault.py tests
python -m unittest discover -s tests -v
~~~

Use a commit subject that describes the change.
Describe the problem, new behavior, checks, and limits in the pull request.
Keep the original license and attribution.

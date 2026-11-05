# Start with ECL-1

ECL-1 specifies a control boundary for consequential AI actions and evidence
that others can check. Choose the first task that matches what you need.

| Your task | Start here | What the result establishes |
| --- | --- | --- |
| Check evidence someone supplied | [Verification quickstart](quickstart.md) | The report's stated integrity, binding and completeness checks under your selected trust policy |
| Understand one mediated workflow | [Runnable bounded workflow](../examples/bounded_workflow/README.md) | A simulated action and failure cases, with newly bound test-key evidence; no deployment conformance claim |
| Integrate your own system | [Integration contract](integration-contract.md), then [minimum L1 path](l1-minimum.md) | The boundaries, responsibilities and requirements your implementation needs to address |
| Assess a claim | [Reviewer guide](reviewer-guide.md) and [decision examples](decision-examples.md) | Procedures for checking implementation evidence, including questions a wire-format test cannot settle |
| Contribute a correction | [Contributing](../governance/CONTRIBUTING.md) | A public proposal with scope, evidence and recorded disposition |

The public package contains the standard, profiles, schemas, evidence,
conformance corpus, three verifiers and the teaching example. The tools can run
without a G-14 account or product. Dependency installation may need network
access; verification runs offline. The licenses and patent pledge are linked
from [LICENSING](../LICENSING.md).

## First implementation exercise

Select one action with a concrete target, operation and parameters. Write down
the System of Interest, action class, authority, credential custody, source
validation and negative boundary before introducing enforcement. Keep existing
safeguards active while comparing decisions against recorded or simulated work.

On the actual implementation, demonstrate an exact admitted effect, denial
without an effect, an approval hold, rejection of a consequential change after
approval, replay and expiry refusal, and loss of required proof at release.
Produce the required evidence and compare the three verifier reports under the
same caller-chosen trust policy and evaluation time.

Record the environment, exact public version/digest, commands, elapsed time,
errors, maintainer assistance and unsupported behavior. A failed or unsupported
case remains visible. Do not call the exercise L1 conformance until all its
applicable requirements and assessment obligations have been satisfied.

An outside developer can report the result using the
[implementation profile](../conformance/EXTERNAL_IMPLEMENTATION_PROFILE.md).
The [implementers registry](../community/implementers.yaml) lists self-declared
claims under the published rules; a listing supplies no certification.

## Check a contribution using public files

After installing the Python verifier, use:

```sh
python scripts/check_public.py --language python
python scripts/check_public.py --language typescript
python scripts/check_public.py --language go
```

Use the Python executable of the environment into which you installed the
verifier. Omitting `--language` runs all three. The TypeScript checks install
locked npm dependencies; all three commands retain their nonzero failures.
The public CI uses the same command. This is the public verification and
teaching-example suite; the release policy defines the additional release
and assessment evidence.

The editors regenerate derived normative artifacts when a contribution needs
tooling outside the public package. Submit the source change and its proposed
expected results; an editor attaches the regenerated diff and checks before
merge. Do not hand-edit generated outputs to claim that regeneration passed.

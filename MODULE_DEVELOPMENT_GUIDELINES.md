# Module Development Guidelines

## Effective From
- Date: March 11, 2026
- Scope: Entire project

## Working Rule
- We will build features module wise from now onward.
- We will not keep adding major logic into a single file.
- Each module must have its own folder, files, and version history.
- Shared business logic must be reused across dashboards instead of rewriting it separately.

## Order Module First
- The `Order` feature will be developed as a separate module.
- This module will contain its own:
  - UI components
  - state/data handling
  - services or API calls
  - validation logic
  - helpers/constants
  - version notes
- After the Order module is ready, it will be imported and used inside:
  - Admin dashboard
  - Staff dashboard
  - Client dashboard

## Architecture Direction
- Keep dashboard files focused on layout, routing, permissions, and module composition.
- Move feature-specific logic into dedicated module folders.
- Avoid large monolithic files for feature implementation.
- Prefer small reusable files over one large combined screen file.

## Suggested Structure
```text
frontend/
  modules/
    orders/
      v1.1/
        components/
        pages/
        services/
        hooks/
        utils/
        constants/
        index.js
        CHANGELOG.md
```

## Versioning Rule
- Versioning will be tracked separately for every module.
- Initial version for each new module starts at `v1.1`.
- After every approved change in that module, increase to the next version:
  - `v1.1`
  - `v1.2`
  - `v1.3`
  - `v1.4`
- Version bumps must be recorded in that module's `CHANGELOG.md`.
- A version update in one module does not force the same update in other modules.

## Order Module Version Plan
| Module | Current Version | Notes |
| --- | --- | --- |
| Order Module | v1.1 | Initial modular split and dashboard integration baseline |

## Dashboard Integration Rule
- Admin, Staff, and Client dashboards should call the same Order module entry points where possible.
- Role-based differences should be handled by configuration, props, permissions, or separate wrapper screens.
- Core order workflows should stay inside the Order module, not inside each dashboard file.

## File Management Rule
- No new major feature should be completed inside one standalone page file.
- If a file becomes too large or mixes multiple responsibilities, split it immediately into module files.
- Shared code must be placed in reusable module-level files.

## Changelog Format
Each module should maintain a changelog like this:

```md
# Order Module Changelog

## v1.1
- Initial module setup
- Connected to admin/staff/client dashboards

## v1.2
- Added next approved change
```

## Immediate Execution Standard
- Start implementation with the Order module as the first modular feature.
- Build it separately.
- Plug it into dashboards after the module interface is ready.
- Continue the same process for future modules.

## Non-Negotiable Safety Rules (Effective Immediately)
- Unless specifically mentioned by the user, do not change the existing look and feel of any page.
- While implementing new functionality, do not delete, remove, or silently alter existing functionality.
- If any new change can impact existing behavior, flows, or UI, explicitly call out the risk first.
- For any potentially breaking impact on existing functionality, proceed only after user confirmation.
- During implementation, preserve backward compatibility of existing routes, actions, and visible controls wherever feasible.

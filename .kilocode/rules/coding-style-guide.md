## Brief overview

This style guide defines the coding standards, organization patterns, and commenting philosophy for the scriptorium project. These guidelines ensure consistency across shell scripts, emphasizing minimal commenting, clear organization, and self-documenting code.

## File organization structure

- Use consistent section dividers:
  - `# ============================================================================` for shell scripts
- Organize all shell scripts with the same structure:
  1. Shebang and script configuration (set -e, etc.)
  2. Constants and global variables
  3. Utility functions
  4. Core business logic
  5. Main execution logic
- Apply section headers with descriptive comments in ALL CAPS
- Group related functions under appropriate sections

## Minimal commenting philosophy

- Use function-level documentation only (brief comments for function purpose)
- Avoid inline comments unless explaining complex logic or non-obvious behavior
- Make code self-documenting through clear naming conventions
- Remove explanatory comments that restate what the code does
- Example: Remove `# Parse the address` before `parse_address "$address"`

## Naming conventions

- **Shell**: `UPPER_CASE` for script-level variables, `snake_case` for function names
- Use descriptive names that eliminate need for comments
- Functions should clearly indicate their purpose through naming

## Function documentation

- **Shell**: Add single-line comment describing function purpose
- Format: `# Brief description of function purpose`
- Keep documentation concise and focused on what, not how

## Visual consistency

- Apply decorative section dividers to all files for visual organization
- Use consistent spacing and indentation:
  - Shell: 4 spaces for indentation
- Maintain uniform logging patterns across the project
- Keep consistent error message formats

## Error handling patterns

- Use consistent exit codes and error propagation patterns
- Maintain uniform error message formatting across shell scripts
- Use proper error handling with meaningful exit codes
- Wrap errors with context when appropriate

## Code maintenance approach

- Prioritize readability over brevity
- Ensure changes maintain consistency across all project files
- Apply style changes systematically to all relevant files
- Review for consistency when adding new functions or sections
- Use shellcheck for script validation and best practices

## Shell script guidelines

- Use `#!/usr/bin/env bash` shebang for portability
- Set `set -e` for error handling (exit on any command failure)
- Set `set -u` to exit on undefined variables (when appropriate)
- Set `set -o pipefail` to catch errors in pipes
- Use consistent variable naming and quoting:
  - Always quote variables: `"$VARIABLE"`
  - Use `${VARIABLE}` for clarity when needed
  - Prefer `[[ ]]` over `[ ]` for conditional tests
- Maintain the same sectioning and commenting approach throughout
- Use `readonly` for constants that shouldn't change
- Validate input parameters and provide usage information
- Use `local` for function variables to avoid global scope pollution
- Handle signals appropriately with trap statements when needed

## Project-specific patterns

- **Script Organization**: Group related functionality into clear sections
- **Configuration**: Use constants for default values and configuration
- **Logging**: Maintain consistent log levels and message formats across components
- **Path Handling**: Use relative paths where appropriate, absolute when necessary
- **Service Management**: Use consistent patterns for service lifecycle management

## Security considerations

- Sanitize user input and validate parameters
- Use proper file permissions (chmod/chown) consistently
- Avoid hardcoded secrets - use environment variables or config files
- Use secure temporary file creation practices
- Validate external dependencies before use
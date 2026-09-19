import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
	// The host-provided harness types are a hand-written shim, not our code to lint.
	{ignores: ['node_modules/**', 'types/**']},
	eslint.configs.recommended,
	tseslint.configs.recommended,
	{
		rules: {
			'@typescript-eslint/no-unused-vars': [
				'error',
				{argsIgnorePattern: '^_', varsIgnorePattern: '^_'},
			],
		},
	},
);

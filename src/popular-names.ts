// The names an attacker would try to be mistaken for.
//
// Generated from fp-bench-results/2026-08-12-v0.2.0.json: the 220 most
// downloaded packages of that run's pool, keeping unscoped names of five
// characters or more. A scoped name cannot be confused with an unscoped one by a
// typo, and short names collide with everything ("ms" is one edit from dozens of
// unrelated packages).
//
// It inherits the sampling bias of the keyword pool that produced it. Regenerate
// from a newer run rather than editing by hand, and re-measure the prevalence of
// the typosquat signal afterwards: a longer list fires more often, and whether
// that is detection or noise is an empirical question.
export const POPULAR_PACKAGE_NAMES: string[] = [
  'ansi-align', 'ansi-escapes', 'ansi-styles', 'argparse', 'async',
  'async-exit-hook', 'async-function', 'async-limiter', 'asynckit',
  'axe-core', 'bluebird', 'bottleneck', 'bowser', 'boxen', 'camelcase-css',
  'clean-css', 'cli-boxes', 'cli-spinners', 'cli-table3', 'cliui',
  'cluster-key-slot', 'comment-json', 'content-type', 'cron-parser',
  'css-minimizer-webpack-plugin', 'cssfilter', 'csv-parse',
  'data-view-buffer', 'data-view-byte-offset', 'decompress-response',
  'define-data-property', 'dezalgo', 'easy-table',
  'embla-carousel-reactive-utils', 'enquirer', 'es-define-property',
  'esast-util-from-estree', 'espree', 'estree-util-build-jsx',
  'estree-util-visit', 'fast-csv', 'fast-string-width', 'fast-xml-parser',
  'fastq', 'fix-dts-default-cjs-exports', 'forwarded-parse', 'fraction.js',
  'get-intrinsic', 'get-tsconfig', 'har-schema', 'has-values',
  'hast-util-sanitize', 'hast-util-to-parse5', 'heap-js', 'htmlparser2',
  'http-assert', 'http-errors', 'http-status-codes', 'icss-utils',
  'import-local', 'inline-style-prefixer', 'is-in-ci', 'is-primitive',
  'is-reference', 'is-retry-allowed', 'is-typedarray', 'json-schema-typed',
  'json-to-pretty-yaml', 'jsonc-eslint-parser', 'kuler', 'kysely',
  'less-loader', 'lines-and-columns', 'listr2', 'lodash.isobject',
  'mdast-util-gfm', 'mdast-util-gfm-task-list-item',
  'mdast-util-mdx-expression', 'mdast-util-phrasing', 'mdast-util-to-hast',
  'mdast-util-to-markdown', 'memfs', 'memoizee', 'meriyah', 'micromark',
  'micromark-extension-mdx-expression', 'micromark-extension-mdx-jsx',
  'micromark-util-resolve-all', 'micromark-util-subtokenize',
  'micromark-util-types', 'mini-css-extract-plugin', 'minimist',
  'module-details-from-path', 'morgan', 'nanostores', 'next-intl', 'nitro',
  'node-releases', 'nth-check', 'nwsapi', 'oauth4webapi', 'object.groupby',
  'openapi-fetch', 'openid-client', 'oxc-parser', 'oxfmt', 'p-cancelable',
  'p-each-series', 'p-event', 'p-is-promise', 'p-limit', 'p-map', 'p-queue',
  'pac-proxy-agent', 'parse-statements', 'parseley', 'path-dirname',
  'path-parse', 'plist', 'portfinder', 'postcss', 'postcss-clamp',
  'postcss-color-rebeccapurple', 'postcss-colormin',
  'postcss-custom-selectors', 'postcss-discard-empty',
  'postcss-flexbugs-fixes', 'postcss-gap-properties', 'postcss-logical',
  'postcss-minify-font-values', 'postcss-minify-gradients',
  'postcss-minify-params', 'postcss-modules-local-by-default',
  'postcss-normalize-positions', 'postcss-opacity-percentage',
  'postcss-overflow-shorthand', 'postcss-page-break',
  'postcss-replace-overflow-wrap', 'postcss-safe-parser', 'postcss-scss',
  'postcss-values-parser', 'postgres-array', 'postgres-bytea',
  'prepend-http', 'proxy-agent', 'query-selector-shadow-dom', 'queue',
  'rc-util', 'react-colorful', 'react-datepicker', 'react-docgen',
  'react-dom', 'react-dropzone', 'react-intersection-observer',
  'react-native', 'react-quill', 'react-redux', 'react-smooth',
  'react-test-renderer', 'react-textarea-autosize', 'react-transition-group',
  'react-use-measure', 'reflect-metadata', 'regex-parser', 'reselect',
  'resize-observer-polyfill', 'run-async', 'set-cookie-parser',
  'set-function-length', 'simple-get', 'skills', 'split-ca',
  'standardwebhooks', 'stoppable', 'stream-http', 'stream-json',
  'string-width', 'string.prototype.trimstart', 'strip-json-comments',
  'style-to-object', 'styled-jsx', 'sucrase', 'supports-hyperlinks',
  'terser', 'tinycolor2', 'ts-toolbelt', 'tsyringe', 'tunnel',
  'typed-assert', 'unbox-primitive', 'unicorn-magic',
  'unist-util-position-from-estree', 'unist-util-stringify-position',
  'unist-util-visit', 'upath', 'url-parse-lax', 'util.promisify', 'wait-on',
  'whatwg-mimetype', 'wrangler', 'wrap-ansi', 'xml-js',]

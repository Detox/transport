/**
 * @package   Detox crypto
 * @author    Nazar Mokrynskyi <nazar@mokrynskyi.com>
 * @copyright Copyright (c) 2017, Nazar Mokrynskyi
 * @license   MIT License, see license.txt
 */
compiler	= require('google-closure-compiler-js').gulp()
fs			= require('fs')
gulp		= require('gulp')

gulp
	.task('minify', ->
		gulp.src('src/index.js')
			.pipe(compiler(
				compilationLevel	: 'ADVANCED'
				externs				: [{src: fs.readFileSync('src/externs.js').toString()}]
				jsOutputFile		: 'index.min.js'
				languageIn			: 'ES5'
				languageOut			: 'ES5'
				warningLevel		: 'VERBOSE'
			))
			.pipe(gulp.dest('src'))
	)

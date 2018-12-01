/**
 * Created by dana on 5/3/15.
 */

module.exports = function(grunt) {

    grunt.initConfig({
        bower_concat: {
            components: {
                dest: 'js/scripts-bower.js',
                cssDest: 'css/styles-bower.css',
                mainFiles: {
                    'cryptojslib': ['rollups/aes.js']
                },
                exclude: [
                    'grunt'
                ]
            }
        },
        concat: {
            components: {
                src: 'js-ext/**/*.js',
                dest: 'js/scripts-ext.js'
            }
        },
        uglify: {
            components: {
                options: {
                    mangle: true,
                    compress: true
                },
                files: {
                    'js/scripts-bower.min.js': 'js/scripts-bower.js',
                    'js/scripts-ext.min.js': 'js/scripts-ext.js',
                    'js/securephrase.min.js': 'js/securephrase.js'
                }
            }
        },
        clean: {
            dist: [ 'deploy/**/*.*' ]
        },
        copy: {
            fonts: {
                files: [
                    {
                        cwd: 'bower_components/bootstrap/dist/fonts/',  // set working folder / root to copy
                        src: '**/*',           // copy all files and subfolders
                        dest: 'fonts/',    // destination folder
                        expand: true           // required when using cwd
                    }
                ]
            },
            dist: {
                files : [
                    { cwd: '', expand: true, src: '*.html', dest: 'dist/' },
                    { cwd: 'css', expand: true, src: '*.css', dest: 'dist/css' },
                    { cwd: 'fonts', expand: true, src: '*.*', dest: 'dist/fonts' },
                    { cwd: 'js', expand: true, src: '*.min.js', dest: 'dist/js' }
                ]
            }
        }
    });

    require('load-grunt-tasks')(grunt);

    grunt.registerTask('default', ['concat', 'bower_concat', 'uglify', 'copy:fonts', 'clean', 'copy:dist']);
    grunt.registerTask('dist', ['clean:dist', 'copy:dist']);

};
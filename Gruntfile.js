/**
 * Created by dana on 5/3/15.
 */

module.exports = function(grunt) {

    grunt.initConfig({
        bower_concat: {
            components: {
                dest: 'js/scripts-bower.js',
                cssDest: 'css/styles-bower.css',
                exclude: [
                    'bitcoinjs-lib'
                ]
            }
        },
        concat: {
            components: {
                src: 'js-ext/**/*.js',
                dest: 'js/scripts-ext.js'
            }
        },
        browserify: {
            bitcoinjs: {
                src: 'bower_components/bitcoinjs-lib/src/index.js',
                dest: 'js/bitcoinjs.js'
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
                    'js/scripts-ext.min.js': 'js/scripts-ext.js'
                }
            }
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
            }
        }
    });

    require('load-grunt-tasks')(grunt);

    grunt.registerTask('default', ['browserify', 'concat', 'bower_concat', 'copy', 'uglify']);

};
/**
 * Created by dana on 5/3/15.
 */

module.exports = function(grunt) {

    grunt.initConfig({
        bower_concat: {
            components: {
                dest: 'js/components.js',
                cssDest: 'css/components.css',
                exclude: [
                    'bitcoinjs-lib'
                ]
            }
        },
        browserify: {
            bitcoinjs: {
                src: 'bower_components/bitcoinjs-lib/src/index.js',
                dest: 'js/gen/bitcoinjs.js'
            }
        },
        uglify: {
            components: {
                options: {
                    mangle: true,
                    compress: true
                },
                files: {
                    'js/gen/components.min.js': 'js/gen/components.js'
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

    grunt.registerTask('default', ['browserify', 'bower_concat', 'copy', 'uglify']);

};
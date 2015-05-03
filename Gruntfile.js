/**
 * Created by dana on 5/3/15.
 */

module.exports = function(grunt) {

    grunt.initConfig({
        bower_concat: {
            all: {
                dest: 'js/components.js'
            }
        },
        uglify: {
            all: {
                options: {
                    mangle: true,
                    compress: true
                },
                files: {
                    'js/components.min.js': 'js/components.js'
                }
            }
        },
        copy: {
            all: {
                files: [
                    {
                        cwd: 'bower_components/bootstrap/dist/css/',  // set working folder / root to copy
                        src: '**/*',           // copy all files and subfolders
                        dest: 'css/',    // destination folder
                        expand: true           // required when using cwd
                    },
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

    grunt.registerTask('default', ['bower_concat', 'copy', 'uglify']);

};
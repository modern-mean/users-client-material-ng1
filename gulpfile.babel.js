'use strict';

import gulp from 'gulp';
import * as modules from 'modern-mean-build-gulp/dist/modules';
import { clientConfig as config } from './src/clientConfig';


function clientConfig(done) {
  process.env.MM_MODULE_CLIENT_CONSTANTS = JSON.stringify(config.constants);
  process.env.MM_MODULE_CLIENT_VALUES = JSON.stringify(config.values);
  process.env.MM_MODULE_ROOT = 'modern-mean-users-material';
  process.env.MM_MODULE_ANGULAR = 'users';
  return done();
}


//Build Client
let client = gulp.series(modules.client.clean, clientConfig, modules.client.build);
client.displayName = 'client';
gulp.task(client);

//Gulp Default
let defaultTask = gulp.parallel(client);
defaultTask.displayName = 'default';
gulp.task(defaultTask);

//Gulp Watch
let watch = gulp.series(defaultTask, modules.watch.all);
watch.displayName = 'watch';
gulp.task(watch);

//Gulp Lint
let lint = gulp.series(modules.lint.all);
lint.displayName = 'lint';
gulp.task(lint);

//Gulp Test
let testTask = gulp.series(modules.lint.all, defaultTask, modules.test.client);
testTask.displayName = 'test';
gulp.task(testTask);

//Gulp Coverage
let coverage = gulp.series(modules.test.coverage);
coverage.displayName = 'coverage';
gulp.task(coverage);

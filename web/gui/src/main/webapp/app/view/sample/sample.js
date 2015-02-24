/*
 * Copyright 2014,2015 Open Networking Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 ONOS GUI -- Sample View Module
 */

(function () {
    'use strict';
    var tbs;

    angular.module('ovSample', ['onosUtil'])
        .controller('OvSampleCtrl', ['$log', 'ToolbarService',
            function (_$log_, _tbs_) {
                var self = this,
                    $log = _$log_,
                    tbs = _tbs_;

                self.message = 'Hey there folks!';

                var toolbar = tbs.createToolbar('sample');
                toolbar.addButton('some-btn', 'crown', function () {});
                toolbar.show();

             $log.log('OvSampleCtrl has been created');
        }]);
}());
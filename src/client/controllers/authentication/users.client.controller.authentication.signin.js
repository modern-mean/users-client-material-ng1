(function() {
  'use strict';

  angular
    .module('users')
    .controller('SigninAuthenticationController', SigninAuthenticationController);

  SigninAuthenticationController.$inject = ['Authentication', '$state', '$mdToast', '$mdDialog','$log'];

  function SigninAuthenticationController(Authentication, $state, $mdToast, $mdDialog, $log) {
    var vm = this;

    vm.authentication = Authentication;
    vm.cancel = cancel;
    vm.clearForm = clearForm;
    vm.credentials = {};
    vm.error = undefined;
    vm.forms = {};
    vm.signin = signin;

    function cancel() {
      $mdDialog.cancel();
    }

    function signin () {
      vm.error = undefined;
      $log.debug('SigninAuthenticationController::signin', vm);
      var toast = $mdToast.simple()
        .position('bottom right')
        .hideDelay(6000);

      Authentication
        .signin(vm.credentials)
        .then(
          function (response) {
            vm.cancel();
            toast.textContent('Signin Successful!').theme('toast-success');
            $mdToast.show(toast);
            vm.clearForm();
            $log.debug('SigninAuthenticationController::signin::success', response);
          },
          function (err) {
            vm.error = err.data.message;
            toast.textContent('Signin Failed!').theme('toast-error');
            $mdToast.show(toast);
            $log.debug('SigninAuthenticationController::signin::error', err);
          }
        );
    }

    function clearForm() {
      vm.credentials.email = '';
      vm.credentials.password = '';
      vm.forms.signIn.$setPristine();
      vm.forms.signIn.$setUntouched();
    }

    $log.info('SigninAuthenticationController::Init', vm);
  }
})();

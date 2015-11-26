var app = angular.module('app', ['ngMaterial']);

app.controller('AppController', function ($mdSidenav) {
    var vm = this;

    vm.toggleSidenav = function (menuId) {
        $mdSidenav(menuId).toggle();
    };

});
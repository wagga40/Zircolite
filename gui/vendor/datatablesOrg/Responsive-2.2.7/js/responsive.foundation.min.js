/*!
 Foundation integration for DataTables' Responsive
 ©2015 SpryMedia Ltd - datatables.net/license
*/
(function(c){"function"===typeof define&&define.amd?define(["jquery","datatables.net-zf","datatables.net-responsive"],function(a){return c(a,window,document)}):"object"===typeof exports?module.exports=function(a,b){a||(a=window);b&&b.fn.dataTable||(b=require("datatables.net-zf")(a,b).$);b.fn.dataTable.Responsive||require("datatables.net-responsive")(a,b);return c(b,a,a.document)}:c(jQuery,window,document)})(function(c,a,b,k){a=c.fn.dataTable;b=a.Responsive.display;var h=b.modal;b.modal=function(d){return function(e,
f,g){c.fn.foundation?f||c('<div class="reveal-modal" data-reveal/>').append('<a class="close-reveal-modal" aria-label="Close">&#215;</a>').append(d&&d.header?"<h4>"+d.header(e)+"</h4>":null).append(g()).appendTo("body").foundation("reveal","open"):h(e,f,g)}};return a.Responsive});

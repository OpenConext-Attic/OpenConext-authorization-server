$('a[data-lang]').click(function (e) {
  e.preventDefault();
  e.stopPropagation();
  var link = $(this);
  var lang = link.data("lang");
  window.location.search = replaceQueryParam("lang",lang, window.location.search);
});

$('a[data-deny]').click(function (e) {
  e.preventDefault();
  e.stopPropagation();
  var link = $(this);
  alert(link.data("error-msg"));
});

function replaceQueryParam(param, newval, search) {
  var regex = new RegExp("([?;&])" + param + "[^&;]*[;&]?");
  var query = search.replace(regex, "$1").replace(/&$/, '');
 return (query.length > 2 ? query + "&" : "?") + (newval ? param + "=" + newval : '');
}

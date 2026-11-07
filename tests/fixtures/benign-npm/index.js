module.exports = function pad(str, len, ch = ' ') {
  str = String(str);
  while (str.length < len) str = ch + str;
  return str;
};

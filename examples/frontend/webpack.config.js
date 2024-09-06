const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
  mode: 'development',
  entry: './src/index.js',
  devServer: {
    hot: true,
    port: 3080,
    open: true,
    static: ['src'],
    historyApiFallback: true,
  },
  plugins: [new HtmlWebpackPlugin({ template: 'src/index.html' })],
};

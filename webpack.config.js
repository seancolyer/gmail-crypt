const CopyWebpackPlugin = require('copy-webpack-plugin');

module.exports = {
  devtool: 'inline-source-map',
  entry: {
    'page-injected': './src/mymail-crypt-page-injected.js',
    'content-script': './src/mymail-crypt.js',
    'background': './src/mymail-crypt-background.js',
    'options': './src/mymail-crypt-options.js'
  },
  output: {
    path: __dirname,
    filename: "dist/js/[name].bundle.js"
  },
  module: {
    preLoaders: [{
      test: /\.js$/,
      loader: 'eslint',
      include: /src/
    }],
    loaders: [{
      test: /\.css$/,
      loader: "style!css"
    }, {
      test: /\.json$/,
      loader: 'json'
    }, {
      test: /\.(eot|svg|ttf|woff|woff2)$/,
      loader: 'file'
    }]
  },
  eslint: {
    failOnWarning: false,
    failOnError: true
  },
  resolve: {
    alias: {
      angular_material_css: `${__dirname}/node_modules/angular-material/angular-material.css`
    }
  },
  plugins: [
    new CopyWebpackPlugin([
      {from: 'src/css', to: 'dist/css'},
      {from: 'src/html', to: 'dist/html'},
      {from: 'src/manifest.json', to: 'dist'},
      {from: 'assets/images', to: 'dist/images'},
      {from: 'assets/fonts', to: 'dist/fonts'}
    ])
  ]
};

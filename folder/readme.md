├── cms-platform/
│   ├── packages/
│   │   ├── core/
│   │   │   ├── src/
│   │   │   │   ├── domains/
│   │   │   │   │   ├── auth/
│   │   │   │   │   │   ├── models/
│   │   │   │   │   │   │   ├── userModel.ts
│   │   │   │   │   │   │   ├── roleModel.ts
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   │   ├── services/
│   │   │   │   │   │   │   ├── authService.ts
│   │   │   │   │   │   │   ├── userService.ts
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   ├── website/
│   │   │   │   │   │   ├── models/
│   │   │   │   │   │   │   ├── websiteModel.ts
│   │   │   │   │   │   │   ├── pageModel.ts
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   │   ├── services/
│   │   │   │   │   │   │   ├── websiteService.ts
│   │   │   │   │   │   │   ├── pageService.ts
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   ├── content/
│   │   │   │   │   │   ├── models/
│   │   │   │   │   │   │   ├── postModel.ts
│   │   │   │   │   │   │   ├── categoryModel.ts
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   │   ├── services/
│   │   │   │   │   │   │   ├── postService.ts
│   │   │   │   │   │   │   ├── categoryService.ts
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   └── ...
│   │   │   │   ├── infrastructure/
│   │   │   │   │   ├── database/
│   │   │   │   │   │   ├── databaseConfig.ts 
│   │   │   │   │   │   └── ...
│   │   │   │   │   ├── eventBus/ 
│   │   │   │   │   │   ├── eventBusConfig.ts 
│   │   │   │   │   │   └── ...
│   │   │   │   │   ├── caching/
│   │   │   │   │   │   ├── cacheConfig.ts 
│   │   │   │   │   │   └── ...
│   │   │   │   │   └── ...
│   │   │   │   ├── middleware/
│   │   │   │   │   ├── authMiddleware.ts
│   │   │   │   │   └── ...
│   │   │   │   ├── controllers/
│   │   │   │   │   ├── authController.ts 
│   │   │   │   │   ├── websiteController.ts
│   │   │   │   │   ├── contentController.ts
│   │   │   │   │   └── ...
│   │   │   │   ├── routes/
│   │   │   │   │   ├── authRoutes.ts 
│   │   │   │   │   ├── websiteRoutes.ts
│   │   │   │   │   ├── contentRoutes.ts 
│   │   │   │   │   └── ...
│   │   │   │   └── app.ts 
│   │   │   └── ... (other files)
│   │   ├── media/
│   │   │   ├── src/ 
│   │   │   │   ├── domains/
│   │   │   │   │   ├── media/
│   │   │   │   │   │   ├── models/
│   │   │   │   │   │   │   ├── mediaModel.ts 
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   │   ├── services/
│   │   │   │   │   │   │   ├── mediaService.ts 
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   └── ...
│   │   │   │   ├── infrastructure/
│   │   │   │   │   ├── storage/
│   │   │   │   │   │   ├── storageConfig.ts 
│   │   │   │   │   │   └── ...
│   │   │   │   └── ...
│   │   │   ├── middleware/
│   │   │   │   └── ...
│   │   │   ├── controllers/
│   │   │   │   ├── mediaController.ts
│   │   │   │   └── ...
│   │   │   ├── routes/
│   │   │   │   ├── mediaRoutes.ts 
│   │   │   │   └── ...
│   │   │   └── app.ts 
│   │   ├── ecommerce/
│   │   │   ├── src/
│   │   │   │   ├── domains/
│   │   │   │   │   ├── ecommerce/
│   │   │   │   │   │   ├── models/
│   │   │   │   │   │   │   ├── productModel.ts
│   │   │   │   │   │   │   ├── orderModel.ts
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   │   ├── services/
│   │   │   │   │   │   │   ├── productService.ts 
│   │   │   │   │   │   │   ├── orderService.ts 
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   └── ...
│   │   │   │   ├── infrastructure/
│   │   │   │   │   ├── payment/
│   │   │   │   │   │   ├── paymentConfig.ts 
│   │   │   │   │   │   └── ...
│   │   │   │   └── ...
│   │   │   ├── middleware/
│   │   │   │   └── ...
│   │   │   ├── controllers/
│   │   │   │   ├── productController.ts
│   │   │   │   ├── orderController.ts
│   │   │   │   └── ...
│   │   │   ├── routes/
│   │   │   │   ├── productRoutes.ts
│   │   │   │   └── ...
│   │   │   └── app.ts
│   │   ├── analytics/
│   │   │   ├── src/
│   │   │   │   ├── domains/
│   │   │   │   │   ├── analytics/
│   │   │   │   │   │   ├── models/
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   │   ├── services/
│   │   │   │   │   │   │   ├── analyticsService.ts 
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   └── ...
│   │   │   │   ├── infrastructure/
│   │   │   │   │   ├── metrics/
│   │   │   │   │   │   ├── metricsConfig.ts 
│   │   │   │   │   │   └── ...
│   │   │   │   └── ...
│   │   │   ├── middleware/
│   │   │   │   └── ...
│   │   │   ├── controllers/
│   │   │   │   ├── analyticsController.ts
│   │   │   │   └── ...
│   │   │   ├── routes/
│   │   │   │   ├── analyticsRoutes.ts 
│   │   │   │   └── ...
│   │   │   └── app.ts
│   │   ├── search/
│   │   │   ├── src/
│   │   │   │   ├── domains/
│   │   │   │   │   ├── search/
│   │   │   │   │   │   ├── models/
│   │   │   │   │   │   │   └── ...
│   │   │   │   │   │   ├── services/
│   │   │   │   │   │   │   ├── searchService.ts 
│   │   │   │   │   │   │   └── ... 
│   │   │   │   │   └── ...
│   │   │   │   ├── infrastructure/
│   │   │   │   │   ├── indexing/ 
│   │   │   │   │   │   ├── indexingConfig.ts 
│   │   │   │   │   │   └── ...
│   │   │   │   └── ...
│   │   │   ├── middleware/
│   │   │   │   └── ...
│   │   │   ├── controllers/
│   │   │   │   ├── searchController.ts 
│   │   │   │   └── ...
│   │   │   ├── routes/
│   │   │   │   ├── searchRoutes.ts 
│   │   │   │   └── ...
│   │   │   └── app.ts
│   │   ├── shared/
│   │   │   ├── src/
│   │   │   │   ├── utils/
│   │   │   │   │   ├── eventBus.ts
│   │   │   │   │   ├── templateRenderer.ts
│   │   │   │   │   ├── renderingService.ts 
│   │   │   │   │   ├── messageBroker.ts
│   │   │   │   │   └── ...
│   │   │   │   ├── models/
│   │   │   │   │   └── ...
│   │   │   │   ├── services/
│   │   │   │   │   └── ...
│   │   │   └── ... (other files) 
│   │   ├── gateways/
│   │   │   ├── src/
│   │   │   │   ├── website-gateway/
│   │   │   │   │   ├── app.ts
│   │   │   │   │   └── ...
│   │   │   │   ├── ecommerce-gateway/
│   │   │   │   │   ├── app.ts
│   │   │   │   │   └── ...
│   │   │   └── ...
│   │   ├── jobs/
│   │   │   ├── src/
│   │   │   │   └── ... 
│   │   │   └── ...
│   │   └── ... (other packages)
│   ├── infrastructure/
│   │   ├── database/
│   │   │   ├── src/
│   │   │   │   ├── config.ts 
│   │   │   │   ├── migrations/
│   │   │   │   │   └── ...
│   │   │   │   ├── seeds/
│   │   │   │   │   └── ...
│   │   │   │   └── ...
│   │   ├── caching/
│   │   │   ├── src/
│   │   │   │   ├── config.ts 
│   │   │   │   └── ...
│   │   ├── storage/
│   │   │   ├── src/
│   │   │   │   ├── config.ts 
│   │   │   │   └── ...
│   │   ├── indexing/
│   │   │   ├── src/
│   │   │   │   ├── config.ts 
│   │   │   │   └── ... 
│   │   ├── metrics/
│   │   │   ├── src/
│   │   │   │   ├── config.ts 
│   │   │   │   └── ...
│   │   ├── payment/
│   │   │   ├── src/
│   │   │   │   ├── config.ts 
│   │   │   │   └── ...
│   │   ├── eventBus/
│   │   │   ├── src/
│   │   │   │   ├── config.ts
│   │   │   │   ├── events/
│   │   │   │   │   └── ... 
│   │   │   │   └── ...
│   │   ├── messageBroker/
│   │   │   ├── src/
│   │   │   │   ├── config.ts  
│   │   │   │   └── ...
│   │   ├── email/ 
│   │   │   ├── src/
│   │   │   │   ├── config.ts
│   │   │   │   └── ... 
│   │   └── ... (other infrastructure)
│   ├── scripts/
│   │   ├── create-db.ts
│   │   ├── seed-db.ts 
│   │   └── ...
│   ├── .env 
│   └── package.json 
├── cms-frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Auth/
│   │   │   │   ├── LoginForm.tsx 
│   │   │   │   └── RegisterForm.tsx
│   │   │   ├── Website/
│   │   │   │   ├── WebsiteEditor.tsx
│   │   │   │   ├── WebsiteSettings.tsx
│   │   │   │   └── ...
│   │   │   ├── Content/
│   │   │   │   ├── PostEditor.tsx
│   │   │   │   └── CategoryEditor.ts 
│   │   │   ├── Media/
│   │   │   │   ├── MediaLibrary.tsx
│   │   │   │   └── UploadMedia.tsx 
│   │   │   ├── E-commerce/
│   │   │   │   ├── ProductEditor.tsx
│   │   │   │   ├── OrderManagement.tsx 
│   │   │   │   └── ...
│   │   │   ├── Analytics/
│   │   │   │   ├── Dashboard.tsx
│   │   │   │   └── Reports.tsx 
│   │   │   ├── Search/ 
│   │   │   │   └── SearchResults.tsx 
│   │   │   └── Shared/ 
│   │   │       ├── Layout.tsx
│   │   │       └── Header.tsx
│   │   ├── pages/
│   │   │   ├── Auth/
│   │   │   │   ├── Login.tsx
│   │   │   │   └── Register.tsx
│   │   │   ├── Website/
│   │   │   │   └── EditWebsite.tsx 
│   │   │   ├── Content/ 
│   │   │   │   └── CreatePost.tsx
│   │   │   ├── Media/ 
│   │   │   │   └── MediaUpload.tsx 
│   │   │   ├── E-commerce/
│   │   │   │   └── CreateProduct.tsx
│   │   │   ├── Analytics/
│   │   │   │   └── AnalyticsOverview.tsx
│   │   │   └── Search/ 
│   │   │       └── SearchPage.tsx
│   │   ├── store/
│   │   │   ├── authStore.ts 
│   │   │   ├── websiteStore.ts
│   │   │   ├── contentStore.ts
│   │   │   └── ... 
│   │   ├── services/
│   │   │   ├── authService.ts
│   │   │   ├── websiteService.ts
│   │   │   ├── contentService.ts 
│   │   │   └── ...
│   │   ├── utils/
│   │   │   └── ...
│   │   └── app.tsx 
│   └── ... (other files)
├── cms-api-client/ 
│   ├── src/ 
│   │   ├── services/
│   │   │   ├── authService.ts 
│   │   │   ├── websiteService.ts
│   │   │   ├── contentService.ts 
│   │   │   └── ...
│   │   └── ... (other files)
│   └── ... (other files)
├── analytics-dashboard/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.tsx
│   │   │   └── Charts/
│   │   │       ├── WebsiteTrafficChart.tsx 
│   │   │       ├── UserEngagementChart.tsx 
│   │   │       └── ...
│   │   ├── pages/ 
│   │   │   └── Index.tsx
│   │   ├── store/
│   │   │   └── analyticsStore.ts
│   │   ├── services/ 
│   │   │   ├── analyticsService.ts 
│   │   │   └── ...
│   │   ├── utils/
│   │   │   └── ...
│   │   └── app.tsx
│   └── ... (other files) 
├── search-engine/ 
│   ├── src/
│   │   ├── services/ 
│   │   │   ├── searchService.ts 
│   │   │   └── ...
│   │   ├── indexing/
│   │   │   ├── src/
│   │   │   │   ├── ...
│   │   │   └── ...
│   │   ├── utils/
│   │   │   └── ... 
│   │   ├── routes/
│   │   │   ├── ...
│   │   └── app.ts 
│   └── ... (other files) 
├── jobs/
│   ├── src/
│   │   ├── ...
│   └── ...
└── ... (other files) 
This is my folder structure, I want command to make it once 

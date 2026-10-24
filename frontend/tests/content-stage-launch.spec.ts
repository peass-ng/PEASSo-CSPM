import { expect, test, type Page } from '@playwright/test';
const LEAK = 'aws.review.workload.selected_image_secret_indicators';
const IMAGE = 'aws.review.ecr.selected_image_vulnerabilities';
async function setup(page: Page, schedule = false) {
 const submitted: any[] = [];
 await page.route('**/api/**', async route => {
  const path = new URL(route.request().url()).pathname;
  if ((path === '/api/scans' || path.startsWith('/api/schedules')) && ['POST','PATCH'].includes(route.request().method())) {
   submitted.push(route.request().postDataJSON());return route.fulfill({status:503,json:{detail:'Captured locally'}});
  }
  const body = path === '/api/health' ? {status:'ok',auth_mode:'local'}
   : path === '/api/me' ? {tenant_id:'fixture'}
   : path === '/api/ai/codex' ? {available:true}
   : path === '/api/connectors' ? {items:[{id:'configured',name:'Configured',provider:'aws',scheduling:{allowed:true},content_scan_checks:{leaks:[LEAK],images:[IMAGE]}},{id:'missing',name:'No targets',provider:'aws',content_scan_checks:{leaks:[],images:[]}}]}
   : path === '/api/catalog/frameworks' ? {framework_versions:[{id:'cis-test',name:'CIS fixture',family:'CIS',provider:'aws'}]}
   : path === '/api/schedules' && schedule ? {items:[{id:'scheduled',name:'Stored image selection',connector_id:'configured',categories:['hardening'],content_checks:[IMAGE],images_enabled:true,leaks_enabled:false,checks:[],frameworks:['CIS'],rules:[{frequency:'daily',time:'10:00'}],timezone:'UTC',enabled:true}]}
   : {items:[]};
  return route.fulfill({json:body});
 });
 await page.goto('/#Scans');
 if (schedule) await page.getByRole('button',{name:'Stored image selection',exact:true}).click();
 else await page.getByRole('button',{name:'Launch scan',exact:true}).click();
 return {submitted,dialog:page.getByRole('dialog')};
}
for (const [leaks,images] of [[true,true],[true,false],[false,true],[false,false]]) {
 test(`independent stages leaks=${leaks} images=${images} preserve H&C filters`,async({page})=>{
  const {dialog,submitted}=await setup(page);
  await dialog.getByRole('checkbox',{name:/^Leaks /}).setChecked(leaks);
  await dialog.getByRole('checkbox',{name:/^Image CVEs /}).setChecked(images);
  await dialog.getByText('Frameworks and checklist versions (optional)',{exact:false}).click();
  await dialog.getByText('Add another framework',{exact:true}).click();
  await dialog.getByRole('button',{name:'CIS · all versions',exact:true}).click();
  await expect(dialog.getByLabel('Check IDs (optional, comma separated)')).toHaveValue('');
  await dialog.getByRole('button',{name:'Start scan',exact:true}).click();
  await expect.poll(()=>submitted.length).toBe(1);
  expect(submitted[0]).toMatchObject({connector_id:'configured',leaks_enabled:leaks,images_enabled:images,frameworks:['CIS'],checks:[]});
  expect(submitted[0].categories).toContain('hardening');
  expect(submitted[0].content_checks).toEqual([...(leaks?[LEAK]:[]),...(images?[IMAGE]:[])]);
 });
}
test('images-only scan needs no H&C category or manual check IDs',async({page})=>{
 const {dialog,submitted}=await setup(page);
 for(const box of await dialog.locator('input[type=checkbox]').all())if(await box.isEnabled())await box.uncheck();
 await dialog.getByRole('checkbox',{name:/^Image CVEs /}).check();
 await dialog.getByRole('button',{name:'Start scan',exact:true}).click();
 await expect.poll(()=>submitted.length).toBe(1);
 expect(submitted[0]).toMatchObject({categories:[],checks:[],content_checks:[IMAGE],leaks_enabled:false,images_enabled:true,ai_enabled:false});
});
test('missing exact targets disable stages and submit false capabilities',async({page})=>{
 const {dialog,submitted}=await setup(page);await dialog.getByRole('combobox',{name:'Connector',exact:true}).selectOption('missing');
 await expect(dialog.getByRole('checkbox',{name:/^Leaks /})).toBeDisabled();
 await expect(dialog.getByRole('checkbox',{name:/^Image CVEs /})).toBeDisabled();
 await dialog.getByRole('button',{name:'Start scan',exact:true}).click();await expect.poll(()=>submitted.length).toBe(1);
 expect(submitted[0]).toMatchObject({content_checks:[],leaks_enabled:false,images_enabled:false});
});
test('editing persisted schedule restores image-only selection and filters',async({page})=>{
 const {dialog,submitted}=await setup(page,true);
 await expect(dialog.getByRole('checkbox',{name:/^Leaks /})).not.toBeChecked();
 await expect(dialog.getByRole('checkbox',{name:/^Image CVEs /})).toBeChecked();
 await dialog.getByRole('button',{name:'Save schedule',exact:true}).click();await expect.poll(()=>submitted.length).toBe(1);
 expect(submitted[0]).toMatchObject({categories:['hardening'],frameworks:['CIS'],content_checks:[IMAGE],leaks_enabled:false,images_enabled:true,timezone:'UTC'});
});

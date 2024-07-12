#include "opencv2/opencv.hpp"
#include <csignal>

#include "global.hpp"
#include "inc/webcam.hpp"

void WebcamCapture(unsigned char webcamNumber ) {

    cv::VideoCapture vcap(webcamNumber); 
      if(!vcap.isOpened())
             return;
      

   int frame_width = vcap.get(cv::CAP_PROP_FRAME_WIDTH);
   int frame_height = vcap.get(cv::CAP_PROP_FRAME_HEIGHT);
   cv::VideoWriter vwriter("out.avi", cv::VideoWriter::fourcc('M','P','4','2'),10, cv::Size(frame_width,frame_height),true);
   //You can try other video codecs. MP42
   //filename, codec, fps, frmae Size, Color

   for(;;){
        //Condition_variable mb
       cv::Mat frame;
       vcap >> frame;
       vwriter.write(frame);
       
       //tread::sleep make it worse 
    }
    return ;
}

void WebcamPick(unsigned char webcamNumber ) {

	cv::VideoCapture vcap(webcamNumber);
	if (!vcap.isOpened())
		return;

	cv::Mat frame;
	vcap >> frame;
	cv::imshow("frame", frame);
	cv::imwrite("peek.png", frame);
}
